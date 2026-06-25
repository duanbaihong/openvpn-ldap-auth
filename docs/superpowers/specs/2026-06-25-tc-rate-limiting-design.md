# TC 带宽限速功能设计

**日期:** 2026-06-25
**作者:** Sisyphus
**状态:** 待审阅

## 背景

openvpn-ldap-auth 插件已有基于 iptables 的组级防火墙策略映射（`src/la_iptables.c`），通过 OpenVPN 的 `LEARN_ADDRESS` 回调在客户端连接/断开时动态应用/清除规则。现需新增**基于 Linux 流量控制（TC）的每用户带宽限速**功能，复用同样的生命周期模式。

### 标注的假设

| 假设 | 依据 |
|------|------|
| "libtc" = libnl-3 / libnl-route-3 的 TC 子模块 | librarian 全面搜索确认无独立 libtc 库；"tc"=traffic control，"低层"=网络层 |
| 配置来源 = YAML + LDAP 混合 | 用户确认（选项 3），与现有 iptables 集成一致 |
| 方案 = HTB 两层分层限速 | 推荐方案，最小可行，后续可扩展组级 |
| 限速方向 = TUN egress（用户下载方向） | HTB qdisc 默认挂载在 egress；ingress（上传）限速需 IFB 镜像，作为扩展点 |
| 限速失败不阻断认证 | best-effort 原则，限速是附加能力 |

## 目标

1. 在 TUN 接口上为每个 VPN 用户设置带宽上限（上行/下行）
2. 支持全局默认限速 + 单用户覆盖配置
3. 配置来自 YAML（静态）+ LDAP（动态）双重来源
4. 复现现有 iptables 集成的生命周期模式（LEARN_ADDRESS hook + 监控线程 reload）

## 非目标

- 组级限速（后续可扩展，本次设计预留扩展点）
- 认证频率限制（本次明确为带宽限速）
- QoS / DSCP 标记

## 架构

### HTB 两层分层限速

在 TUN 接口上创建 HTB（Hierarchy Token Bucket）qdisc：

```
TUN 接口 (ifindex from envp["dev"])
└── HTB root qdisc (handle 1:)
    ├── root class 1:1  ← 全局限速 (rate/ceil)
    │   ├── class 1:100  ← 用户A (rate=1Mbps, ceil=2Mbps) + u32 filter src=10.8.0.2
    │   ├── class 1:101  ← 用户B (rate=2Mbps, ceil=5Mbps) + u32 filter src=10.8.0.3
    │   └── class 1:102  ← 用户C (继承全局) + u32 filter src=10.8.0.4
    └── default 1:1     ← 未匹配流量走 root class（全局限速兜底）
```

**带宽借用**：空闲用户的剩余带宽自动分配给活跃用户（HTB 核心特性），提高带宽利用率。

### 为什么选 HTB 而非 TBF

| 维度 | HTB | TBF |
|------|-----|-----|
| 分层支持 | 支持（root → child class） | 不支持（单一 qdisc） |
| 带宽借用 | 支持 | 不支持 |
| per-user 限速 | 每用户一个 child class + filter | 需要 iptables MARK 交织 |
| 全局+单用户继承 | 天然支持（child 继承 parent） | 需要手动同步两个独立配置 |

## 组件

### 1. `src/la_tc.h` / `src/la_tc.c` — TC 操作封装

**公开 API：**

```c
typedef struct rate_limit_config {
    uint32_t rate_bps;    /* 保证速率（字节/秒） */
    uint32_t ceil_bps;    /* 最大速率（字节/秒） */
} rate_limit_config_t;

typedef struct tc_context {
    struct nl_sock *nl_sock;
    int             tun_ifindex;
    uint32_t        next_classid;   /* 递增分配器，从 100 开始 */
    /* IP → classid 映射表（简单数组或 hash） */
} tc_context_t;

/* 生命周期 */
int  la_tc_init(const char *tun_dev, rate_limit_config_t *global);
void la_tc_shutdown(void);

/* 每用户操作（LEARN_ADDRESS hook 调用） */
int  la_tc_user_add(const char *client_ip, rate_limit_config_t *user_rl);
int  la_tc_user_delete(const char *client_ip);

/* 配置 reload（监控线程调用） */
int  la_tc_reload_global(rate_limit_config_t *new_global);
```

**私有函数（la_tc.c 内部）：**

- `create_htb_root_qdisc(ifindex)` — 创建 HTB root qdisc (handle 1:) + root class 1:1
- `create_user_class(classid, rate, ceil)` — 创建 child class
- `add_ip_filter(src_ip, classid)` — 添加 u32 filter，按源 IP 路由到对应 class
- `delete_user_class(classid)` — 删除 child class（filter 随之自动删除）
- `parse_bandwidth(const char *str)` — 解析 "2Mbps"/"512Kbps" → 字节/秒
- `lookup_classid_by_ip(ip)` — 从映射表查找
- `alloc_classid()` / `free_classid(classid)` — classid 池管理

### 2. `src/cnf.h` / `src/cnf.c` — 配置结构扩展

**profile_config_t 新增字段：**

```c
/* TC rate limiting */
ternary_t   tc_enabled;           /* 是否启用 TC 限速 */
char       *tc_global_rate;       /* YAML: 全局保证速率，如 "10Mbps" */
char       *tc_global_ceil;       /* YAML: 全局最大速率，如 "50Mbps" */
char       *tc_user_rate_attr;    /* LDAP 属性名：用户保证速率 */
char       *tc_user_ceil_attr;    /* LDAP 属性名：用户最大速率 */
```

**YAML 格式（新增 ratelimits: 段）：**

```yaml
ratelimits:
  TC_ENABLED: "yes"
  GLOBAL_RATE: "10Mbps"
  GLOBAL_CEIL: "50Mbps"
  USER_RATE_ATTR: "userRxRate"
  USER_CEIL_ATTR: "userRxCeil"
```

**YAML 单用户覆盖（静态配置）：**

```yaml
ratelimits:
  USER_OVERRIDE:
    - username: "alice"
      rate: "2Mbps"
      ceil: "5Mbps"
    - username: "bob"
      rate: "1Mbps"
```

**cnf.c 需修改的函数：**
- `profile_config_new()` — 初始化新字段
- `profile_config_free()` — 释放新字段
- `profile_config_dup()` — 复制新字段
- `config_parse_file()` — 解析 YAML 键值
- `config_dump()` — 调试输出

### 3. `src/client_context.h` — 客户端上下文扩展

**client_context_t 新增字段：**

```c
rate_limit_config_t *rate_limit;  /* 从 LDAP/YAML 获取的该用户限速配置 */
```

在认证阶段填充，在 LEARN_ADDRESS 阶段读取。

### 4. `src/ldap-auth.c` — Hook 集成

**openvpn_plugin_open_v2：**
- 检测 `tc_enabled == TERN_TRUE` → 调用 `la_tc_init(dev, global_rl)`
- 启用现有监控线程或新增独立 TC 监控线程

**openvpn_plugin_func_v2 — LEARN_ADDRESS 分支：**

| 子事件 | 操作 |
|--------|------|
| `add` | `la_tc_user_add(argv[2], cc->rate_limit)` |
| `delete` | `la_tc_user_delete(argv[2])` |
| `update` | 先 `la_tc_user_delete(old_ip)` 再 `la_tc_user_add(new_ip, cc->rate_limit)` |

**openvpn_plugin_close_v1：**
- `la_tc_shutdown()`

## 数据流

```
启动阶段
  openvpn_plugin_open_v2()
    ├─ config_parse_file() → 解析 YAML ratelimits: 段
    ├─ la_tc_init(dev, global_ratelimit)
    │   ├─ nl_socket_alloc() + nl_connect(NETLINK_ROUTE)
    │   ├─ if_nametoindex(dev) → tun_ifindex
    │   ├─ create_htb_root_qdisc(tun_ifindex)
    │   └─ create root class 1:1 (global rate/ceil)
    └─ 启动/复用监控线程

认证阶段
  la_ldap_handle_authentication()
    ├─ ldap_find_user() → 获取 userdn
    ├─ ldap_binddn() → 验证密码
    ├─ 查询 LDAP 用户限速属性 (userRxRate/userRxCeil)
    │   → 存入 client_context->rate_limit
    └─ YAML 单用户覆盖优先于 LDAP

连接阶段 (LEARN_ADDRESS add)
  openvpn_plugin_func_v2(LEARN_ADDRESS, "add")
    ├─ 从 client_context 读取 cc->rate_limit
    └─ la_tc_user_add(client_ip, cc->rate_limit)
        ├─ alloc_classid() → 分配 classid
        ├─ create_user_class(classid, rate, ceil)
        └─ add_ip_filter(client_ip, classid)

断开阶段 (LEARN_ADDRESS delete)
  openvpn_plugin_func_v2(LEARN_ADDRESS, "delete")
    └─ la_tc_user_delete(client_ip)
        ├─ lookup_classid_by_ip(ip)
        ├─ delete_user_class(classid)
        └─ free_classid(classid)

Reload 阶段 (监控线程 60s)
  la_tc_reload_global(new_global)
    ├─ 更新 root class 1:1 的 rate/ceil
    └─ 遍历在线用户，按新配置更新各 user class
```

## 配置优先级

```
YAML 单用户覆盖 (USER_OVERRIDE)
    ↓ 未配置则
LDAP 用户属性 (userRxRate/userRxCeil)
    ↓ 未配置则
YAML 全局默认 (GLOBAL_RATE/GLOBAL_CEIL)
```

## classid 管理策略

- 范围：`100 ~ 65534`（避开 root 的 1:1）
- 分配：递增计数器 `next_classid`，从 100 开始
- 回收：维护 `IP → classid` 映射表（简单数组或 hash），delete 时释放
- 耗尽处理：LOGERROR，新用户降级到 root class（全局限速兜底）

## 错误处理

| 场景 | 处理 |
|------|------|
| libnl 初始化失败 | LOGERROR，`tc_enabled` 降级为 false，不影响认证 |
| 创建 qdisc/class 失败 | LOGERROR，该用户不限速（走 default class），不阻断连接 |
| classid 耗尽 | LOGERROR，新用户走 root class（全局限速） |
| LDAP 限速属性缺失 | 回退到全局默认 |
| 带宽值解析失败 | LOGWARNING，回退到全局默认 |
| delete 时 class 不存在 | LOGWARNING，忽略（幂等） |

**核心原则：限速是 best-effort，永远不阻断认证或连接。**

## 构建集成

### configure.in 新增

```autoconf
PKG_CHECK_MODULES([LIBNL], [libnl-3.0 libnl-route-3.0], [
    have_libnl=yes
], [
    AC_MSG_WARN([libnl-3 not found, traffic control disabled])
    have_libnl=no
])
AM_CONDITIONAL([HAVE_LIBNL], [test "$have_libnl" = yes])
```

### src/Makefile.am 新增

```makefile
if HAVE_LIBNL
libopenvpn_ldap_auth_la_SOURCES += la_tc.c
libopenvpn_ldap_auth_la_CFLAGS  += $(LIBNL_CFLAGS)
libopenvpn_ldap_auth_la_LIBADD  += $(LIBNL_LIBS)
endif
```

运行时若无 libnl，插件仍可正常编译运行，限速功能自动禁用。

## 测试策略

- **手动验证**：连接用户 → `tc -s class show dev tun0` 查看 class → `iperf3` 测带宽
- **边界测试**：用户断开后 class 是否清理；reload 后配置是否更新
- **降级测试**：libnl 不可用时认证是否正常工作
- **并发测试**：多用户同时连接/断开，classid 分配无冲突

## 扩展点

- **组级限速**：在 root class (1:1) 和 user class 之间插入 group class (1:10, 1:20...)，LDAP 组的 cn 映射为 group class，用户 class 挂在所属组 class 下
- **双向独立限速**：当前设计仅限 TUN egress（服务器→用户，即下载方向）。如需限制上传（ingress），需通过 IFB（Intermediate Functional Block）镜像 ingress 流量到 egress qdisc，或在物理网卡上设置对称规则
- **QoS 标记**：在 filter 中添加 DSCP 设置

## 涉及文件

| 文件 | 改动类型 |
|------|----------|
| `src/la_tc.h` | 新增 |
| `src/la_tc.c` | 新增 |
| `src/cnf.h` | 修改：profile_config_t 新增字段 |
| `src/cnf.c` | 修改：init/free/dup/parse/dump |
| `src/client_context.h` | 修改：新增 rate_limit 字段 |
| `src/ldap-auth.c` | 修改：hook 集成 |
| `configure.in` | 修改：libnl 依赖检测 |
| `src/Makefile.am` | 修改：条件编译 la_tc.c |
