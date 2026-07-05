# TC 带宽限速功能设计 v2

**日期:** 2026-07-05
**状态:** 待审阅

## 背景

OpenVPN LDAP 认证插件需要基于 libnl-3 TC (HTB qdisc) 的每用户带宽限速。前次实现因线程安全问题（LEARN_ADDRESS 回调与 reload 线程并发访问 ConnVpnQueue_r）导致 segfault。本设计解决线程安全并重新实现。

## 线程安全方案（核心变更）

**reload 只更新全局 root class，不遍历在线用户队列。** 零阻塞，零风险。

- TC init/shutdown：启动和关闭时单线程，无竞态
- `la_tc_user_add/delete`：由 LEARN_ADDRESS 回调调用，持 `g_tc.lock` 仅毫秒级（链表操作 + classid 分配 + netlink I/O）
- `la_tc_reload`：只调用 `la_tc_reload_global()` 更新 root class，不访问 `ConnVpnQueue_r`
- 组策略变化：用户重连时用新配置创建 TC class

无 action_mutex 加锁，无队列遍历，无死锁风险。

## 架构

HTB 两层分层限速，TUN 接口上：

```
TUN 接口
└── HTB root qdisc (handle 1:)
    ├── root class 1:1  ← 全局限速
    │   ├── class 1:100 ← 用户A + u32 filter src=10.8.0.2
    │   └── class 1:101 ← 用户B + u32 filter src=10.8.0.3
    └── default 1:1
```

`ceil = rate`（无带宽借用，硬限速）。

## 优先级链

```
LDAP 组 (groupRxLimitRate)      ← 最高
    ↓
LDAP 用户 (userRxLimitRate)
    ↓
YAML 组 (TC_GROUP_LIMIT_RATE)
    ↓
YAML 全局 (TC_GLOBAL_LIMIT_RATE) ← 最低
```

取第一个非零值。认证阶段解析后存入 `client_context->rate_limit`，LEARN_ADDRESS(add) 时传给 `la_tc_user_add`。

## 配置格式

YAML 顶层段（与 LDAP: / IPTABLERULES: 同级）：

```yaml
TC_LIMIT_ENABLED           : True
TC_GLOBAL_LIMIT_RATE       : 100Mbps
TC_USER_RATE_LDAP_ATTR     : userRxLimitRate
TC_GROUP_RATE_LDAP_ATTR    : groupRxLimitRate
# 优先级: LDAP组 > LDAP用户 > YAML组 > YAML全局
TC_GROUP_LIMIT_RATE:
  vpn-admin: 20Mbps
  vpn-development: 5Mbps
  vpn-common: 2Mbps
```

## 新增文件

### src/la_tc.h
- `rate_limit_config_t`（只有 `rate_bps`，无 ceil）
- `parse_bandwidth()` 声明
- `la_tc_init/shutdown/user_add/user_delete/reload_global` 声明
- 无 libnl 时 `static inline` stub

### src/la_tc.c
- `g_tc` 全局上下文（nl_sock, ifindex, classid 池, ip_map, pthread_mutex）
- `parse_bandwidth()` — 只接受 Gbps/Mbps/Kbps/bps
- `create_htb_root()` / `delete_htb_root()`
- `create_user_class()` / `delete_user_class()` / `add_ip_filter()`
- `alloc_classid()` / `lookup_classid()` / `add_ip_mapping()` / `remove_ip_mapping()`
- 公开 API 实现

## 修改文件

| 文件 | 改动 |
|------|------|
| `configure.in` | `--enable-tc` + libnl-3 检测 |
| `src/Makefile.am` | `la_tc.c` 编译 + libnl 链接 |
| `src/ldap-auth.c` | LEARN_ADDRESS TC hook + 启动/关闭（不加 action_mutex） |
| `src/la_ldap.c` | LDAP 组/用户限速查询 + 优先级链 + la_tc_reload |
| `src/la_iptables.c` | reload 末尾调用 la_tc_reload |
| `src/cnf.h/c` | TC 配置字段 + keymaps + 解析 |
| `src/client_context.h/c` | rate_limit 字段 |
| `src/queue.h/c` | VpnConnGroups 加 rate_limit |

## 60s reload 流程

```
监控线程 (action_mutex)
  ├── config_load_ldap_groups_profiles()  ← LDAP 组限速刷新
  ├── iptables 规则增删
  ├── la_tc_reload_yaml()                 ← 重解析 YAML
  └── la_tc_reload()                      ← 只更新全局 root class
      └── la_tc_reload_global()           ← 不遍历队列，零阻塞
```

## 带宽值验证

`parse_bandwidth()` 只接受 `Gbps`/`Mbps`/`Kbps`/`bps`，转为字节/秒。纯数字、单字母、空值返回 0。

## 错误处理

- libnl 不可用 → stub no-op
- TC 初始化失败 → tc_enabled 降级 false
- class 创建失败 → 用户走 default class
- 限速是 best-effort，不阻断认证
