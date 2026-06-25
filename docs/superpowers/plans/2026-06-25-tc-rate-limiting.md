# TC 带宽限速功能实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 OpenVPN LDAP 认证插件中新增基于 libnl TC (HTB qdisc) 的每用户带宽限速功能

**Architecture:** 在 TUN 接口上创建 HTB root qdisc + root class (全局限速)，每用户连接时创建 child class + u32 filter (单用户限速)，断开时删除。配置来自 YAML + LDAP 混合，复用现有 LEARN_ADDRESS hook 生命周期。

**Tech Stack:** C11, autotools (autoconf/automake), libnl-3 / libnl-route-3, pthread

## Global Constraints

- 缩进 2 空格，expandtab（来自 vim modeline）
- CFLAGS 硬编码 `-Wall -Werror`（不允许 warning）
- 类型命名 `snake_case_t`，函数 `snake_case`，库函数前缀 `la_`
- 头文件保护 `_NAME_H_` 格式
- 依赖：libldap, liblber, libyaml, pthread, libnl-3, libnl-route-3
- 限速失败不阻断认证（best-effort 原则）
- libnl 不可用时自动降级（条件编译 `HAVE_LIBNL`）

---

## File Structure

| 文件 | 责任 | 改动类型 |
|------|------|----------|
| `src/la_tc.h` | TC 限速 API 声明 + `rate_limit_config_t` 结构 | 新增 |
| `src/la_tc.c` | TC 限速实现：netlink 操作、HTB qdisc/class/filter 管理、classid 池 | 新增 |
| `src/cnf.h` | `profile_config_t` 新增 TC 配置字段 | 修改 |
| `src/cnf.c` | TC 配置字段的 init/free/dup/parse/dump | 修改 |
| `src/client_context.h` | `client_context_t` 新增 `rate_limit` 字段 | 修改 |
| `src/ldap-auth.c` | LEARN_ADDRESS hook 集成 + 启动/关闭集成 | 修改 |
| `configure.in` | libnl 依赖检测 + `HAVE_LIBNL` 条件 | 修改 |
| `src/Makefile.am` | 条件编译 `la_tc.c` + libnl 链接 | 修改 |

---

### Task 1: 构建配置 — libnl 依赖检测

**Files:**
- Modify: `configure.in`
- Modify: `src/Makefile.am`

**Interfaces:**
- Produces: `HAVE_LIBNL` 宏（供 C 代码条件编译）、`LIBNL_CFLAGS` / `LIBNL_LIBS` 变量（供 Makefile.am 使用）

- [ ] **Step 1: 在 configure.in 中添加 libnl 检测**

在 `configure.in` 的 `AC_CHECK_HEADERS([syslog.h sys/resource.h])` 行之后、`AC_PROG_INSTALL` 之前插入：

```autoconf
dnl libnl-3 for traffic control
PKG_CHECK_MODULES([LIBNL], [libnl-3.0 libnl-route-3.0], [
    have_libnl=yes
    AC_DEFINE(HAVE_LIBNL, 1, [Define if libnl-3 is available])
], [
    AC_MSG_WARN([libnl-3 not found, traffic control support disabled])
    have_libnl=no
])
AM_CONDITIONAL([HAVE_LIBNL], [test "$have_libnl" = yes])
```

- [ ] **Step 2: 在 configure.in 的 echo 输出中添加 libnl 状态**

在 `configure.in` 末尾的 echo 块中，`LDAP user conf:` 行之前添加：

```autoconf
   Traffic control (libnl):                            ${have_libnl}
```

- [ ] **Step 3: 修改 src/Makefile.am 添加条件编译**

在 `src/Makefile.am` 的 `EXTRA_DIST` 行之后追加：

```makefile
if HAVE_LIBNL
libopenvpn_ldap_auth_la_SOURCES += la_tc.h la_tc.c
libopenvpn_ldap_auth_la_CFLAGS  += $(LIBNL_CFLAGS)
libopenvpn_ldap_auth_la_LIBADD  += $(LIBNL_LIBS)
endif
```

- [ ] **Step 4: 验证 configure 可运行**

Run: `autoreconf -i && ./configure 2>&1 | grep -i libnl`
Expected: 输出包含 `Traffic control (libnl): yes` 或 `checking for libnl...` 相关行（取决于系统是否安装 libnl-3）

- [ ] **Step 5: Commit**

```bash
git add configure.in src/Makefile.am
git commit -m "build: add libnl-3 dependency detection for TC rate limiting"
```

---

### Task 2: TC 头文件 — la_tc.h

**Files:**
- Create: `src/la_tc.h`

**Interfaces:**
- Produces: `rate_limit_config_t` 结构、`la_tc_init` / `la_tc_shutdown` / `la_tc_user_add` / `la_tc_user_delete` / `la_tc_reload_global` 函数声明

- [ ] **Step 1: 创建 src/la_tc.h**

```c
/**
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 * la_tc.h
 * Traffic control (HTB qdisc) based per-user bandwidth limiting.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */
#ifndef _LA_TC_H_
#define _LA_TC_H_

#include "config.h"

#ifdef HAVE_LIBNL

#include <stdint.h>

/* 带宽限速配置（字节/秒） */
typedef struct rate_limit_config {
  uint32_t  rate_bps;    /* 保证速率 */
  uint32_t  ceil_bps;    /* 最大速率 */
} rate_limit_config_t;

/**
 * 初始化 TC 限速：创建 netlink socket，在 TUN 接口上建立 HTB root qdisc + root class。
 * tun_dev: TUN 接口名（从 OpenVPN envp["dev"] 获取）
 * global: 全局限速配置（rate/ceil），可为 NULL 表示不限速
 * 返回 0 成功，非 0 失败
 */
extern int  la_tc_init(const char *tun_dev, rate_limit_config_t *global);

/**
 * 关闭 TC 限速：删除 root qdisc 及所有 child class，关闭 netlink socket。
 */
extern void la_tc_shutdown(void);

/**
 * 为用户创建限速 class + u32 filter。
 * client_ip: 用户分配的 VPN IP
 * user_rl: 用户限速配置，可为 NULL 表示继承全局
 * 返回 0 成功，非 0 失败（失败时不阻断连接，用户走 default class）
 */
extern int  la_tc_user_add(const char *client_ip, rate_limit_config_t *user_rl);

/**
 * 删除用户的限速 class + filter，释放 classid。
 * client_ip: 用户分配的 VPN IP
 * 返回 0 成功，非 0 失败（幂等，class 不存在时返回 0）
 */
extern int  la_tc_user_delete(const char *client_ip);

/**
 * 更新全局限速配置（reload 时调用）。
 * 更新 root class 的 rate/ceil，并遍历在线用户按新配置更新各 user class。
 * new_global: 新的全局限速配置
 * 返回 0 成功，非 0 失败
 */
extern int  la_tc_reload_global(rate_limit_config_t *new_global);

#endif /* HAVE_LIBNL */

#endif /* _LA_TC_H_ */
```

- [ ] **Step 2: Commit**

```bash
git add src/la_tc.h
git commit -m "feat(tc): add la_tc.h header for bandwidth limiting API"
```

---

### Task 3: TC 实现 — 基础设施与带宽解析

**Files:**
- Create: `src/la_tc.c`
- Create: `tests/test_parse_bandwidth.c`

**Interfaces:**
- Consumes: `la_tc.h` 中的 `rate_limit_config_t`
- Produces: `parse_bandwidth` 函数（内部，parse "2Mbps" → 字节/秒）

- [ ] **Step 1: 创建 tests/test_parse_bandwidth.c 测试文件**

```c
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 声明被测函数 */
uint32_t parse_bandwidth(const char *str);

int main(void) {
  /* "10Mbps" → 1,250,000 bytes/s (10,000,000 bits / 8) */
  assert(parse_bandwidth("10Mbps") == 1250000);
  /* "2Mbps" → 250,000 bytes/s */
  assert(parse_bandwidth("2Mbps") == 250000);
  /* "512Kbps" → 64,000 bytes/s */
  assert(parse_bandwidth("512Kbps") == 64000);
  /* "100Mbps" → 12,500,000 bytes/s */
  assert(parse_bandwidth("100Mbps") == 12500000);
  /* "1Gbps" → 125,000,000 bytes/s */
  assert(parse_bandwidth("1Gbps") == 125000000);
  /* 纯数字无单位 → 假设为 bps */
  assert(parse_bandwidth("1000000") == 125000);
  /* NULL → 0 */
  assert(parse_bandwidth(NULL) == 0);
  /* 空字符串 → 0 */
  assert(parse_bandwidth("") == 0);
  /* 无法解析 → 0 */
  assert(parse_bandwidth("invalid") == 0);

  printf("All parse_bandwidth tests passed.\n");
  return 0;
}
```

- [ ] **Step 2: 创建 src/la_tc.c 骨架 + parse_bandwidth 实现**

```c
/**
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 * la_tc.c
 * Traffic control (HTB qdisc) based per-user bandwidth limiting.
 * Uses libnl-3 / libnl-route-3 rtnetlink API.
 */
#include "config.h"

#ifdef HAVE_LIBNL

#include "la_tc.h"
#include "debug.h"
#include "utils.h"

#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/qdisc/htb.h>
#include <netlink/route/class.h>
#include <netlink/route/tc.h>
#include <linux/pkt_sched.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <net/if.h>

/* classid 范围：100 ~ 65534（避开 root 的 1:1） */
#define TC_CLASSID_MIN    100
#define TC_CLASSID_MAX    65534
#define TC_HTB_HANDLE     TC_H_MAKE(1, 0)
#define TC_ROOT_CLASSID   TC_H_MAKE(1, 1)

/* IP → classid 映射表项 */
typedef struct ip_classid_map {
  char     ip[46];       /* IPv4/IPv6 字符串 */
  uint32_t classid;
  struct ip_classid_map *next;
} ip_classid_map_t;

/* 全局 TC 上下文（模块内单例） */
static struct {
  struct nl_sock     *nl_sock;
  int                 tun_ifindex;
  uint32_t            next_classid;
  ip_classid_map_t   *ip_map;       /* 链表头 */
  rate_limit_config_t global_rl;
  int                 initialized;
} g_tc = {0};

/**
 * 解析带宽字符串为字节/秒。
 * 支持格式: "10Mbps", "512Kbps", "1Gbps", "1000000" (bps)
 * 返回: 字节/秒，解析失败返回 0
 */
uint32_t
parse_bandwidth(const char *str) {
  if (!str || !*str) return 0;

  char unit[8] = {0};
  double value;
  int matched;

  /* 尝试匹配 数字+单位 或 纯数字 */
  matched = sscanf(str, "%lf%7s", &value, unit);
  if (matched < 1) return 0;

  /* 转换为 bps（比特/秒） */
  double bps;
  if (matched == 1) {
    /* 纯数字，假设为 bps */
    bps = value;
  } else {
    /* 大小写不敏感比较单位 */
    if (!strcasecmp(unit, "bps")) {
      bps = value;
    } else if (!strcasecmp(unit, "kbps") || !strcasecmp(unit, "k")) {
      bps = value * 1000;
    } else if (!strcasecmp(unit, "mbps") || !strcasecmp(unit, "m")) {
      bps = value * 1000000;
    } else if (!strcasecmp(unit, "gbps") || !strcasecmp(unit, "g")) {
      bps = value * 1000000000;
    } else {
      return 0;  /* 未知单位 */
    }
  }

  /* bps → bytes/s */
  return (uint32_t)(bps / 8);
}

/* === 后续 Task 填充其余函数 === */

#endif /* HAVE_LIBNL */
```

- [ ] **Step 3: 编写测试 Makefile 规则**

在 `tests/Makefile.am` 的 `openvpn_ldap_search_LDADD` 行之后追加：

```makefile
if HAVE_LIBNL
noinst_PROGRAMS += test_parse_bandwidth
test_parse_bandwidth_SOURCES = test_parse_bandwidth.c
test_parse_bandwidth_LDADD = $(top_srcdir)/src/.libs/libopenvpn-ldap-auth.a $(LIBNL_LIBS)
test_parse_bandwidth_CFLAGS = $(LIBNL_CFLAGS) -I$(top_srcdir)/src
endif
```

- [ ] **Step 4: 编译并运行测试**

Run: `autoreconf -i && ./configure && make -C src && make -C tests test_parse_bandwidth && ./tests/test_parse_bandwidth`
Expected: 输出 `All parse_bandwidth tests passed.`

- [ ] **Step 5: Commit**

```bash
git add src/la_tc.c tests/test_parse_bandwidth.c tests/Makefile.am
git commit -m "feat(tc): add parse_bandwidth with unit parsing and tests"
```

---

### Task 4: TC 实现 — init/shutdown

**Files:**
- Modify: `src/la_tc.c`

**Interfaces:**
- Consumes: `la_tc.h` 声明的 `la_tc_init` / `la_tc_shutdown`
- Produces: `la_tc_init` / `la_tc_shutdown` 实现，`g_tc` 全局上下文初始化

- [ ] **Step 1: 在 la_tc.c 的 parse_bandwidth 函数之后，添加内部辅助函数**

```c
/* === 内部辅助函数 === */

/* 创建 HTB root qdisc + root class */
static int
create_htb_root(const char *tun_dev, rate_limit_config_t *global) {
  struct rtnl_qdisc *qdisc;
  struct rtnl_class *rclass;
  struct rtnl_tc *tc;
  int err;

  /* 获取接口 ifindex */
  g_tc.tun_ifindex = if_nametoindex(tun_dev);
  if (g_tc.tun_ifindex == 0) {
    LOGERROR("la_tc: interface %s not found: %s", tun_dev, strerror(errno));
    return -1;
  }

  /* 创建 HTB root qdisc (handle 1:) */
  qdisc = rtnl_qdisc_alloc();
  if (!qdisc) return -1;
  tc = TC_CAST(qdisc);
  rtnl_tc_set_ifindex(tc, g_tc.tun_ifindex);
  rtnl_tc_set_handle(tc, TC_HTB_HANDLE);
  rtnl_tc_set_kind(tc, "htb");
  rtnl_htb_set_defcls(qdisc, TC_ROOT_CLASSID);  /* 默认走 root class */
  rtnl_htb_set_rate2quantum(qdisc, 1);
  err = rtnl_qdisc_add(g_tc.nl_sock, qdisc, NLM_F_CREATE | NLM_F_REPLACE);
  rtnl_qdisc_put(qdisc);
  if (err != 0) {
    LOGERROR("la_tc: failed to create HTB root qdisc: %s", nl_geterror(err));
    return err;
  }

  /* 创建 root class 1:1（全局限速） */
  rclass = rtnl_class_alloc();
  if (!rclass) return -1;
  tc = TC_CAST(rclass);
  rtnl_tc_set_ifindex(tc, g_tc.tun_ifindex);
  rtnl_tc_set_kind(tc, "htb");
  rtnl_tc_set_handle(tc, TC_ROOT_CLASSID);
  rtnl_tc_set_parent(tc, TC_HTB_HANDLE);
  if (global) {
    rtnl_htb_set_rate(rclass, global->rate_bps);
    rtnl_htb_set_ceil(rclass, global->ceil_bps ? global->ceil_bps : global->rate_bps);
  }
  err = rtnl_class_add(g_tc.nl_sock, rclass, NLM_F_CREATE | NLM_F_REPLACE);
  rtnl_class_put(rclass);
  if (err != 0) {
    LOGERROR("la_tc: failed to create root class: %s", nl_geterror(err));
    return err;
  }

  LOGINFO("la_tc: HTB root qdisc created on %s (ifindex %d)", tun_dev, g_tc.tun_ifindex);
  return 0;
}

/* 删除 root qdisc（清理所有 class/filter） */
static void
delete_htb_root(void) {
  struct rtnl_qdisc *qdisc;
  struct rtnl_tc *tc;

  qdisc = rtnl_qdisc_alloc();
  if (!qdisc) return;
  tc = TC_CAST(qdisc);
  rtnl_tc_set_ifindex(tc, g_tc.tun_ifindex);
  rtnl_tc_set_handle(tc, TC_HTB_HANDLE);
  rtnl_tc_set_kind(tc, "htb");
  rtnl_qdisc_delete(g_tc.nl_sock, qdisc);
  rtnl_qdisc_put(qdisc);
}
```

- [ ] **Step 2: 添加 la_tc_init / la_tc_shutdown 实现**

```c
/* === 公开 API === */

int
la_tc_init(const char *tun_dev, rate_limit_config_t *global) {
  int err;

  if (!tun_dev) {
    LOGERROR("la_tc_init: tun_dev is NULL");
    return -1;
  }

  /* 初始化 netlink socket */
  g_tc.nl_sock = nl_socket_alloc();
  if (!g_tc.nl_sock) {
    LOGERROR("la_tc_init: nl_socket_alloc failed");
    return -1;
  }
  err = nl_connect(g_tc.nl_sock, NETLINK_ROUTE);
  if (err != 0) {
    LOGERROR("la_tc_init: nl_connect failed: %s", nl_geterror(err));
    nl_socket_free(g_tc.nl_sock);
    g_tc.nl_sock = NULL;
    return err;
  }

  /* 保存全局限速配置 */
  if (global) {
    g_tc.global_rl = *global;
  } else {
    memset(&g_tc.global_rl, 0, sizeof(g_tc.global_rl));
  }

  /* 创建 HTB root qdisc + root class */
  err = create_htb_root(tun_dev, global);
  if (err != 0) {
    nl_socket_free(g_tc.nl_sock);
    g_tc.nl_sock = NULL;
    return err;
  }

  g_tc.next_classid = TC_CLASSID_MIN;
  g_tc.ip_map = NULL;
  g_tc.initialized = 1;

  LOGINFO("la_tc: initialized on %s", tun_dev);
  return 0;
}

void
la_tc_shutdown(void) {
  if (!g_tc.initialized) return;

  /* 删除 root qdisc（连带所有 child class + filter） */
  delete_htb_root();

  /* 释放 IP→classid 映射表 */
  ip_classid_map_t *cur = g_tc.ip_map;
  while (cur) {
    ip_classid_map_t *next = cur->next;
    la_free(cur);
    cur = next;
  }
  g_tc.ip_map = NULL;

  /* 关闭 netlink socket */
  if (g_tc.nl_sock) {
    nl_socket_free(g_tc.nl_sock);
    g_tc.nl_sock = NULL;
  }

  g_tc.initialized = 0;
  LOGINFO("la_tc: shutdown complete");
}
```

- [ ] **Step 3: 编译验证**

Run: `make -C src 2>&1 | tail -5`
Expected: 无错误（可能有 unused function warning for la_tc_user_add/delete/reload_global 尚未实现，但因为在头文件声明了所以链接时需要——暂时在 la_tc.c 底部加 stub）

在 la_tc.c 底部 `#endif` 之前添加 stub：

```c
/* Stubs — 将在后续 Task 实现 */
int la_tc_user_add(const char *client_ip, rate_limit_config_t *user_rl) {
  (void)client_ip; (void)user_rl;
  return 0;
}
int la_tc_user_delete(const char *client_ip) {
  (void)client_ip;
  return 0;
}
int la_tc_reload_global(rate_limit_config_t *new_global) {
  (void)new_global;
  return 0;
}
```

Run: `make -C src 2>&1 | tail -5`
Expected: Exit code 0（`-Werror` 无 warning）

- [ ] **Step 4: Commit**

```bash
git add src/la_tc.c
git commit -m "feat(tc): implement la_tc_init/shutdown with HTB root qdisc"
```

---

### Task 5: TC 实现 — per-user class + filter + classid 管理

**Files:**
- Modify: `src/la_tc.c`

**Interfaces:**
- Consumes: `g_tc` 上下文，`la_tc.h` 声明
- Produces: `la_tc_user_add` / `la_tc_user_delete` 完整实现，classid 分配/回收，IP→classid 映射

- [ ] **Step 1: 添加 classid 管理内部函数**

在 la_tc.c 的 `delete_htb_root` 函数之后、`/* === 公开 API === */` 之前插入：

```c
/* === classid 管理 === */

/* 分配一个可用 classid，返回 0 表示耗尽 */
static uint32_t
alloc_classid(void) {
  if (g_tc.next_classid > TC_CLASSID_MAX) {
    return 0;  /* 耗尽 */
  }
  return g_tc.next_classid++;
}

/* 查找 IP 对应的 classid，找到返回 classid，未找到返回 0 */
static uint32_t
lookup_classid(const char *ip) {
  ip_classid_map_t *cur = g_tc.ip_map;
  while (cur) {
    if (strcmp(cur->ip, ip) == 0) return cur->classid;
    cur = cur->next;
  }
  return 0;
}

/* 添加 IP→classid 映射 */
static int
add_ip_mapping(const char *ip, uint32_t classid) {
  ip_classid_map_t *entry = la_malloc(sizeof(ip_classid_map_t));
  if (!entry) return -1;
  strncpy(entry->ip, ip, sizeof(entry->ip) - 1);
  entry->ip[sizeof(entry->ip) - 1] = '\0';
  entry->classid = classid;
  entry->next = g_tc.ip_map;
  g_tc.ip_map = entry;
  return 0;
}

/* 删除 IP→classid 映射，返回被移除的 classid，未找到返回 0 */
static uint32_t
remove_ip_mapping(const char *ip) {
  ip_classid_map_t **pp = &g_tc.ip_map;
  while (*pp) {
    if (strcmp((*pp)->ip, ip) == 0) {
      ip_classid_map_t *entry = *pp;
      uint32_t classid = entry->classid;
      *pp = entry->next;
      la_free(entry);
      return classid;
    }
    pp = &(*pp)->next;
  }
  return 0;
}
```

- [ ] **Step 2: 添加创建/删除 user class 的内部函数**

在上面的 classid 管理函数之后插入：

```c
/* === HTB class + filter 操作 === */

/* 创建 user child class (1:N) + u32 filter */
static int
create_user_class(uint32_t classid, uint32_t rate, uint32_t ceil) {
  struct rtnl_class *rclass;
  struct rtnl_tc *tc;
  int err;

  rclass = rtnl_class_alloc();
  if (!rclass) return -1;
  tc = TC_CAST(rclass);
  rtnl_tc_set_ifindex(tc, g_tc.tun_ifindex);
  rtnl_tc_set_kind(tc, "htb");
  rtnl_tc_set_handle(tc, TC_H_MAKE(1, classid));
  rtnl_tc_set_parent(tc, TC_ROOT_CLASSID);
  rtnl_htb_set_rate(rclass, rate);
  rtnl_htb_set_ceil(rclass, ceil ? ceil : rate);
  err = rtnl_class_add(g_tc.nl_sock, rclass, NLM_F_CREATE);
  rtnl_class_put(rclass);
  if (err != 0) {
    LOGERROR("la_tc: create_user_class(%u) failed: %s", classid, nl_geterror(err));
  }
  return err;
}

/* 删除 user child class（filter 随 class 自动删除） */
static int
delete_user_class(uint32_t classid) {
  struct rtnl_class *rclass;
  struct rtnl_tc *tc;
  int err;

  rclass = rtnl_class_alloc();
  if (!rclass) return -1;
  tc = TC_CAST(rclass);
  rtnl_tc_set_ifindex(tc, g_tc.tun_ifindex);
  rtnl_tc_set_kind(tc, "htb");
  rtnl_tc_set_handle(tc, TC_H_MAKE(1, classid));
  err = rtnl_class_delete(g_tc.nl_sock, rclass);
  rtnl_class_put(rclass);
  if (err != 0 && err != -NLE_OBJ_NOTFOUND) {
    LOGERROR("la_tc: delete_user_class(%u) failed: %s", classid, nl_geterror(err));
  }
  return err;
}

/* 添加 u32 filter：将 src IP 流量路由到指定 class */
static int
add_ip_filter(uint32_t src_ip_n, uint32_t classid) {
  struct rtnl_cls *cls;
  struct rtnl_tc *tc;
  int err;

  cls = rtnl_cls_alloc();
  if (!cls) return -1;
  tc = TC_CAST(cls);
  rtnl_tc_set_ifindex(tc, g_tc.tun_ifindex);
  rtnl_tc_set_handle(tc, TC_H_MAKE(1, classid));
  rtnl_tc_set_parent(tc, TC_HTB_HANDLE);
  rtnl_tc_set_kind(tc, "u32");

  /* match src IP */
  rtnl_tc_set_opts(tc, NULL);
  err = rtnl_u32_add_key_uint32(cls, RTNL_U32_SRC_IP, src_ip_n, 0xFFFFFFFF, 0);
  if (err != 0) {
    LOGERROR("la_tc: u32 add key failed: %s", nl_geterror(err));
    rtnl_cls_put(cls);
    return err;
  }
  rtnl_u32_set_classid(cls, TC_H_MAKE(1, classid));

  err = rtnl_cls_add(g_tc.nl_sock, cls, NLM_F_CREATE);
  rtnl_cls_put(cls);
  if (err != 0) {
    LOGERROR("la_tc: add_ip_filter(%u) failed: %s", classid, nl_geterror(err));
  }
  return err;
}
```

> **注意：** `rtnl_u32_add_key_uint32` 和 `RTNL_U32_SRC_IP` 的确切 API 名称可能因 libnl 版本不同有差异。实施时需查阅 `netlink/route/cls/u32.h` 头文件确认。如果该 API 不可用，替代方案是用 `rtnl_u32_add_key(cls, &src_ip, &mask, U32_KEY_ATTR_SRC_IP, 0)`（接受原始字节）。

- [ ] **Step 3: 替换 la_tc_user_add / la_tc_user_delete 的 stub 为完整实现**

将 la_tc.c 底部的 stub 替换为：

```c
int
la_tc_user_add(const char *client_ip, rate_limit_config_t *user_rl) {
  if (!g_tc.initialized || !g_tc.nl_sock) {
    LOGDEBUG("la_tc: not initialized, skipping user_add");
    return 0;  /* best-effort: 不阻断 */
  }
  if (!client_ip) {
    LOGERROR("la_tc_user_add: client_ip is NULL");
    return -1;
  }

  /* 如果已存在映射，先删除旧 class */
  uint32_t existing = lookup_classid(client_ip);
  if (existing) {
    LOGWARNING("la_tc: IP %s already has classid %u, deleting old", client_ip, existing);
    delete_user_class(existing);
    remove_ip_mapping(client_ip);
  }

  /* 分配新 classid */
  uint32_t classid = alloc_classid();
  if (classid == 0) {
    LOGERROR("la_tc: classid exhausted, user %s falls back to root class", client_ip);
    return -1;  /* 走 default class（全局限速兜底） */
  }

  /* 确定限速参数：user_rl > global */
  uint32_t rate = (user_rl && user_rl->rate_bps) ? user_rl->rate_bps : g_tc.global_rl.rate_bps;
  uint32_t ceil = (user_rl && user_rl->ceil_bps) ? user_rl->ceil_bps : g_tc.global_rl.ceil_bps;
  if (rate == 0) {
    LOGDEBUG("la_tc: no rate configured for %s, using global or skipping", client_ip);
    /* 不创建 class，走 default */
    return 0;
  }

  /* IP 字符串 → 网络字节序 uint32 */
  struct in_addr addr;
  if (inet_pton(AF_INET, client_ip, &addr) != 1) {
    LOGERROR("la_tc: invalid IP %s", client_ip);
    la_free((void*)(uintptr_t)classid);  /* nothing to free for uint */
    return -1;
  }

  /* 创建 child class */
  int err = create_user_class(classid, rate, ceil);
  if (err != 0) {
    return err;  /* class 创建失败，走 default */
  }

  /* 添加 u32 filter */
  err = add_ip_filter(addr.s_addr, classid);
  if (err != 0) {
    delete_user_class(classid);  /* 清理半成品 */
    return err;
  }

  /* 记录映射 */
  if (add_ip_mapping(client_ip, classid) != 0) {
    delete_user_class(classid);
    return -1;
  }

  LOGINFO("la_tc: user %s → classid %u (rate=%u, ceil=%u)", client_ip, classid, rate, ceil);
  return 0;
}

int
la_tc_user_delete(const char *client_ip) {
  if (!g_tc.initialized || !client_ip) return 0;

  uint32_t classid = remove_ip_mapping(client_ip);
  if (classid == 0) {
    LOGDEBUG("la_tc: IP %s not found in mapping, skip delete", client_ip);
    return 0;  /* 幂等 */
  }

  delete_user_class(classid);
  LOGINFO("la_tc: user %s removed (classid %u)", client_ip, classid);
  return 0;
}
```

- [ ] **Step 4: 编译验证（无 -Werror warning）**

Run: `make -C src CFLAGS="-g -Wall -Werror -D_GNU_SOURCE -DHAVE_CONFIG_H" 2>&1 | tail -10`
Expected: Exit code 0，无 warning

> 如果出现 `rtnl_u32_add_key_uint32` 或 `RTNL_U32_SRC_IP` 未声明错误，需查阅系统 `netlink/route/cls/u32.h` 头文件，替换为实际可用的 API。常见替代：`rtnl_u32_add_key(cls, &addr.s_addr, &(uint32_t){0xFFFFFFFF}, sizeof(uint32_t), 0)`。

- [ ] **Step 5: 手动验证（需 root + TUN 接口）**

Run: `sudo tc qdisc show dev tun0 2>/dev/null || echo "No tun0 - defer to integration test"`
Expected: 在实际 OpenVPN 环境中会有 HTB qdisc 输出

- [ ] **Step 6: Commit**

```bash
git add src/la_tc.c
git commit -m "feat(tc): implement per-user HTB class+filter with classid pool"
```

---

### Task 6: TC 实现 — reload_global

**Files:**
- Modify: `src/la_tc.c`

**Interfaces:**
- Consumes: `g_tc` 上下文，IP→classid 映射表
- Produces: `la_tc_reload_global` 实现

- [ ] **Step 1: 替换 la_tc_reload_global stub**

将底部 stub 替换为：

```c
int
la_tc_reload_global(rate_limit_config_t *new_global) {
  if (!g_tc.initialized) return 0;

  /* 更新全局配置 */
  if (new_global) {
    g_tc.global_rl = *new_global;
  }

  /* 更新 root class 1:1 的 rate/ceil */
  struct rtnl_class *rclass = rtnl_class_alloc();
  if (!rclass) return -1;
  struct rtnl_tc *tc = TC_CAST(rclass);
  rtnl_tc_set_ifindex(tc, g_tc.tun_ifindex);
  rtnl_tc_set_kind(tc, "htb");
  rtnl_tc_set_handle(tc, TC_ROOT_CLASSID);
  rtnl_tc_set_parent(tc, TC_HTB_HANDLE);
  if (new_global) {
    rtnl_htb_set_rate(rclass, new_global->rate_bps);
    rtnl_htb_set_ceil(rclass, new_global->ceil_bps ? new_global->ceil_bps : new_global->rate_bps);
  }
  int err = rtnl_class_add(g_tc.nl_sock, rclass, NLM_F_REPLACE);
  rtnl_class_put(rclass);
  if (err != 0) {
    LOGERROR("la_tc: reload_global root class failed: %s", nl_geterror(err));
  }

  /* 遍历在线用户，更新各 user class（继承全局的会更新，有独立配置的保留） */
  /* 注意：此函数只更新 root class，各 user class 的更新需在
   * 监控线程中重新从 LDAP/YAML 获取各用户配置后单独调用 la_tc_user_add
   * （会先删后建）。此处仅更新全局兜底值。 */

  LOGINFO("la_tc: global rate reloaded (rate=%u, ceil=%u)",
          g_tc.global_rl.rate_bps, g_tc.global_rl.ceil_bps);
  return err;
}
```

- [ ] **Step 2: 编译验证**

Run: `make -C src 2>&1 | tail -5`
Expected: Exit code 0

- [ ] **Step 3: Commit**

```bash
git add src/la_tc.c
git commit -m "feat(tc): implement la_tc_reload_global for root class update"
```

---

### Task 7: 配置结构扩展 — cnf.h + cnf.c

**Files:**
- Modify: `src/cnf.h`
- Modify: `src/cnf.c`

**Interfaces:**
- Produces: `profile_config_t` 的 `tc_enabled` / `tc_global_rate` / `tc_global_ceil` / `tc_user_rate_attr` / `tc_user_ceil_attr` 字段

- [ ] **Step 1: 在 cnf.h 的 profile_config_t 中添加 TC 字段**

在 `cnf.h` 的 `profile_config_t` 结构体中，`iptable_rules_field` 之后、`LdapIptableRoles *iptable_rules` 之前添加：

```c
  /* TC rate limiting */
  ternary_t   tc_enabled;
  char        *tc_global_rate;
  char        *tc_global_ceil;
  char        *tc_user_rate_attr;
  char        *tc_user_ceil_attr;
```

- [ ] **Step 2: 在 cnf.c 的 profile_config_free 中添加释放**

在 `cnf.c` 的 `profile_config_free` 函数中，`check_and_free(c->iptable_rules_field)` 之后添加：

```c
  /* TC */
  check_and_free( c->tc_global_rate );
  check_and_free( c->tc_global_ceil );
  check_and_free( c->tc_user_rate_attr );
  check_and_free( c->tc_user_ceil_attr );
```

- [ ] **Step 3: 在 cnf.c 的 profile_config_dup 中添加复制**

在 `profile_config_dup` 函数中，`if( c->iptable_rules_field ) nc->iptable_rules_field = strdup(...)` 之后添加：

```c
  /* TC */
  nc->tc_enabled = c->tc_enabled;
  if( c->tc_global_rate ) nc->tc_global_rate = strdup( c->tc_global_rate );
  if( c->tc_global_ceil ) nc->tc_global_ceil = strdup( c->tc_global_ceil );
  if( c->tc_user_rate_attr ) nc->tc_user_rate_attr = strdup( c->tc_user_rate_attr );
  if( c->tc_user_ceil_attr ) nc->tc_user_ceil_attr = strdup( c->tc_user_ceil_attr );
```

- [ ] **Step 4: 在 cnf.c 的 profile_config_new 中添加初始化**

在 `profile_config_new` 函数中，`c->enable_ldap_iptable=TERN_UNDEF;` 之后添加：

```c
  c->tc_enabled = TERN_UNDEF;
```

- [ ] **Step 5: 在 cnf.c 的 config_parse_file 中添加 YAML 解析**

在 `config_parse_file` 函数中，`IPTABLE_RULES_FIELD` 分支之后、`GROUP_MAP_FIELD` 分支之前添加：

```c
    }else if( !strcasecmp(tname, "TC_ENABLED" ) ){
      p->tc_enabled = string_to_ternary(ldapconfig->keymaps[i].value[0]);
    }else if( !strcasecmp(tname, "TC_GLOBAL_RATE" ) ){
      STRDUP_IFNOTSET(p->tc_global_rate, ldapconfig->keymaps[i].value[0] );
    }else if( !strcasecmp(tname, "TC_GLOBAL_CEIL" ) ){
      STRDUP_IFNOTSET(p->tc_global_ceil, ldapconfig->keymaps[i].value[0] );
    }else if( !strcasecmp(tname, "TC_USER_RATE_ATTR" ) ){
      STRDUP_IFNOTSET(p->tc_user_rate_attr, ldapconfig->keymaps[i].value[0] );
    }else if( !strcasecmp(tname, "TC_USER_CEIL_ATTR" ) ){
      STRDUP_IFNOTSET(p->tc_user_ceil_attr, ldapconfig->keymaps[i].value[0] );
```

- [ ] **Step 6: 在 cnf.c 的 config_dump 中添加调试输出**

在 `config_dump` 函数中，`LOGDEBUG_IFSET(p->iptable_rules_field,...)` 之后添加：

```c
    LOGDEBUG_IFSET(ternary_to_string(p->tc_enabled), "  TC Enabled");
    LOGDEBUG_IFSET(p->tc_global_rate, "  TC Global Rate");
    LOGDEBUG_IFSET(p->tc_global_ceil, "  TC Global Ceil");
    LOGDEBUG_IFSET(p->tc_user_rate_attr, "  TC User Rate Attr");
    LOGDEBUG_IFSET(p->tc_user_ceil_attr, "  TC User Ceil Attr");
```

- [ ] **Step 7: 编译验证**

Run: `make -C src 2>&1 | tail -5`
Expected: Exit code 0

- [ ] **Step 8: Commit**

```bash
git add src/cnf.h src/cnf.c
git commit -m "feat(tc): add TC config fields to profile_config_t with YAML parsing"
```

---

### Task 8: client_context 扩展

**Files:**
- Modify: `src/client_context.h`
- Modify: `src/client_context.c`

**Interfaces:**
- Produces: `client_context_t.rate_limit` 字段

- [ ] **Step 1: 在 client_context.h 中添加 rate_limit 字段**

在 `client_context.h` 的 `client_context_t` 结构体中，`struct Vpn_Conn_Groups_t *groups;` 之后添加：

```c
  struct rate_limit_config *rate_limit;  /* TC 限速配置（从 LDAP/YAML 获取） */
```

并在文件顶部 `#include "cnf.h"` 之后添加（条件编译）：

```c
#ifdef HAVE_LIBNL
#include "la_tc.h"
#endif
```

- [ ] **Step 2: 在 client_context.c 的 free 函数中添加释放**

先读取 `client_context.c` 确认 free 函数的结构，然后在 `client_context_free` 中添加：

```c
#ifdef HAVE_LIBNL
  if( cc->rate_limit ) la_free( cc->rate_limit );
#endif
```

- [ ] **Step 3: 编译验证**

Run: `make -C src 2>&1 | tail -5`
Expected: Exit code 0

- [ ] **Step 4: Commit**

```bash
git add src/client_context.h src/client_context.c
git commit -m "feat(tc): add rate_limit field to client_context_t"
```

---

### Task 9: LDAP 属性查询填充限速配置

**Files:**
- Modify: `src/la_ldap.c`

**Interfaces:**
- Consumes: `client_context_t.rate_limit`（Task 8 定义），`profile_config_t.tc_user_rate_attr/ceil_attr`（Task 7 定义），`parse_bandwidth`（Task 3 实现）
- Produces: 在认证阶段填充 `cc->rate_limit`

- [ ] **Step 1: 在 la_ldap.c 顶部添加 la_tc.h include（条件编译）**

在 `#include "la_iptables.h"` 所在的 include 区域（如果有的话）或在 `#include "client_context.h"` 之后添加：

```c
#ifdef HAVE_LIBNL
#include "la_tc.h"
#endif
```

> 注意：`la_ldap.c` 当前可能没有 include `la_iptables.h`。在此文件已有的 include 区域末尾、`#ifdef ENABLE_LDAPUSERCONF` 之前添加即可。

- [ ] **Step 2: 在 la_ldap_handle_authentication 中添加 LDAP 限速属性查询**

在 `la_ldap_handle_authentication` 函数中，认证成功后的 `la_ldap_handle_pf_file(config, client_context, auth_context->pf_file)` 调用之后、组过滤检查之前，添加：

```c
#ifdef HAVE_LIBNL
        /* 查询 LDAP 用户限速属性，填充 client_context->rate_limit */
        if( client_context->profile->tc_enabled == TERN_TRUE
            && (client_context->profile->tc_user_rate_attr
                || client_context->profile->tc_user_ceil_attr) ){
          rate_limit_config_t *rl = la_malloc( sizeof(rate_limit_config_t) );
          if( rl ){
            la_memset( rl, 0, sizeof(rate_limit_config_t) );
            char *rate_str = NULL;
            char *ceil_str = NULL;

            /* 查询用户 DN 的限速属性 */
            char *attrs[3];
            int ai = 0;
            if( client_context->profile->tc_user_rate_attr )
              attrs[ai++] = client_context->profile->tc_user_rate_attr;
            if( client_context->profile->tc_user_ceil_attr )
              attrs[ai++] = client_context->profile->tc_user_ceil_attr;
            attrs[ai] = NULL;

            if( ai > 0 ){
              struct timeval timeout;
              la_ldap_set_timeout( config, &timeout );
              LDAPMessage *rl_result = NULL;
              rc = ldap_search_ext_s( ldap, userdn, LDAP_SCOPE_BASE,
                                      "(objectClass=*)", attrs, 0,
                                      NULL, NULL, &timeout, 1, &rl_result );
              if( rc == LDAP_SUCCESS && rl_result ){
                LDAPMessage *entry = ldap_first_entry( ldap, rl_result );
                if( entry ){
                  BerElement *ber = NULL;
                  char *attr;
                  for( attr = ldap_first_attribute( ldap, entry, &ber );
                       attr != NULL;
                       attr = ldap_next_attribute( ldap, entry, ber ) ){
                    struct berval **vals = ldap_get_values_len( ldap, entry, attr );
                    if( vals && ldap_count_values_len(vals) > 0 ){
                      if( client_context->profile->tc_user_rate_attr
                          && !strcasecmp(attr, client_context->profile->tc_user_rate_attr) ){
                        rate_str = strndup( vals[0]->bv_val, vals[0]->bv_len );
                      } else if( client_context->profile->tc_user_ceil_attr
                          && !strcasecmp(attr, client_context->profile->tc_user_ceil_attr) ){
                        ceil_str = strndup( vals[0]->bv_val, vals[0]->bv_len );
                      }
                    }
                    if( vals ) ldap_value_free_len( vals );
                    ldap_memfree( attr );
                  }
                  if( ber ) ber_free( ber, 0 );
                }
                ldap_msgfree( rl_result );
              }

              /* 解析带宽字符串 */
              if( rate_str ){
                rl->rate_bps = parse_bandwidth( rate_str );
                la_free( rate_str );
              }
              if( ceil_str ){
                rl->ceil_bps = parse_bandwidth( ceil_str );
                la_free( ceil_str );
              }
            }
            client_context->rate_limit = rl;
            LOGDEBUG("la_ldap: user %s rate_limit rate=%u ceil=%u",
                     auth_context->username, rl->rate_bps, rl->ceil_bps);
          }
        }
#endif /* HAVE_LIBNL */
```

- [ ] **Step 3: 编译验证**

Run: `make -C src 2>&1 | tail -10`
Expected: Exit code 0，无 `-Werror` 警告

- [ ] **Step 4: Commit**

```bash
git add src/la_ldap.c
git commit -m "feat(tc): query LDAP user rate attributes during authentication"
```

---

### Task 10: hook 集成 — ldap-auth.c

**Files:**
- Modify: `src/ldap-auth.c`

**Interfaces:**
- Consumes: `la_tc_init/shutdown/user_add/user_delete`，`profile_config_t.tc_*`，`client_context_t.rate_limit`
- Produces: LEARN_ADDRESS hook 中的 TC 调用，openvpn_plugin_open_v2 中的初始化

- [ ] **Step 1: 在 ldap-auth.c 顶部添加 la_tc.h include**

在 `#include "la_iptables.h"` 之后添加：

```c
#ifdef HAVE_LIBNL
#include "la_tc.h"
#endif
```

- [ ] **Step 2: 在 openvpn_plugin_open_v2 中添加 TC 初始化**

在 `openvpn_plugin_open_v2` 中，`la_iptables_start_monitor(context)` 之后（或 `config_init_iptable_rules(tlp)` 之后）添加：

```c
#ifdef HAVE_LIBNL
  /* 初始化 TC 限速 */
  if( pro_fd->tc_enabled == TERN_TRUE ){
    rate_limit_config_t global_rl = {0};
    if( pro_fd->tc_global_rate )
      global_rl.rate_bps = parse_bandwidth( pro_fd->tc_global_rate );
    if( pro_fd->tc_global_ceil )
      global_rl.ceil_bps = parse_bandwidth( pro_fd->tc_global_ceil );
    if( la_tc_init( openvpnserverinfo->dev, &global_rl ) != 0 ){
      LOGERROR("TC init failed, rate limiting disabled");
      pro_fd->tc_enabled = TERN_FALSE;
    }
  }
#endif
```

- [ ] **Step 3: 在 LEARN_ADDRESS add 分支中添加 la_tc_user_add 调用**

在 `openvpn_plugin_func_v2` 的 `LEARN_ADDRESS` 分支，`add` 子分支中，`la_learn_roles_add(con_value)` 之后添加：

```c
#ifdef HAVE_LIBNL
          if(cc->profile->tc_enabled == TERN_TRUE){
            la_tc_user_add(con_value->ip, cc->rate_limit);
          }
#endif
```

- [ ] **Step 4: 在 LEARN_ADDRESS delete 分支中添加 la_tc_user_delete 调用**

在 `delete` 子分支中，`la_learn_roles_delete(cleanvalue)` 之前添加：

```c
#ifdef HAVE_LIBNL
        if(cc->profile->tc_enabled == TERN_TRUE){
          la_tc_user_delete(cleanvalue->ip);
        }
#endif
```

- [ ] **Step 5: 在 LEARN_ADDRESS update 分支中添加先删后加**

在 `update` 子分支中，`la_learn_roles_delete(old_value)` 之后、创建 `new_value` 之后的 `la_learn_roles_add(new_value)` 之后添加：

```c
#ifdef HAVE_LIBNL
          if(cc->profile->tc_enabled == TERN_TRUE){
            la_tc_user_delete(old_value->ip);
            la_tc_user_add(new_value->ip, cc->rate_limit);
          }
#endif
```

- [ ] **Step 6: 在 openvpn_plugin_close_v1 中添加 la_tc_shutdown**

在 `openvpn_plugin_close_v1` 中，`la_iptables_stop_monitor()` 之后添加：

```c
#ifdef HAVE_LIBNL
  la_tc_shutdown();
#endif
```

- [ ] **Step 7: 编译验证**

Run: `make -C src 2>&1 | tail -10`
Expected: Exit code 0

- [ ] **Step 8: Commit**

```bash
git add src/ldap-auth.c
git commit -m "feat(tc): integrate TC rate limiting into OpenVPN plugin lifecycle"
```

---

### Task 11: 集成验证

**Files:**
- 无新文件

- [ ] **Step 1: 完整构建**

Run: `autoreconf -i && ./configure && make 2>&1 | tail -20`
Expected: 全部编译成功，无 `-Werror` 警告

- [ ] **Step 2: 检查 configure 输出**

Run: `./config.status --config 2>&1 | grep -i libnl || grep -i libnl config.log`
Expected: 看到 `have_libnl=yes`

- [ ] **Step 3: 运行 parse_bandwidth 单元测试**

Run: `./tests/test_parse_bandwidth`
Expected: `All parse_bandwidth tests passed.`

- [ ] **Step 4: 手动集成测试（需 OpenVPN + LDAP 环境）**

在 `/etc/openvpn/openvpn-ldap.yaml` 中添加：

```yaml
ratelimits:
  TC_ENABLED: "yes"
  GLOBAL_RATE: "10Mbps"
  GLOBAL_CEIL: "50Mbps"
  TC_USER_RATE_ATTR: "userRxRate"
  TC_USER_CEIL_ATTR: "userRxCeil"
```

启动 OpenVPN，连接一个用户，然后运行：

```bash
tc qdisc show dev tun0
tc class show dev tun0
tc filter show dev tun0
```

Expected: 看到 HTB qdisc，root class 1:1 和 user class 1:100，u32 filter

用 `iperf3` 测带宽验证限速生效。

- [ ] **Step 5: 验证断开清理**

断开 VPN 用户，运行：

```bash
tc class show dev tun0
```

Expected: 对应 user class 已删除

- [ ] **Step 6: Commit（如果有最终调整）**

```bash
git add -A
git commit -m "test(tc): integration verified"
```
