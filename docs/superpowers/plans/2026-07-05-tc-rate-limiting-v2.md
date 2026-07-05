# TC 带宽限速功能 v2 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 OpenVPN LDAP 认证插件中新增基于 libnl-3 TC (HTB qdisc) 的每用户带宽限速

**Architecture:** HTB root qdisc + root class (全局限速) + per-user child class + u32 filter (按源 IP 路由)。reload 只更新 root class，不遍历队列。ceil=rate 无带宽借用。

**Tech Stack:** C11, autotools, libnl-3/libnl-route-3, pthread

## Global Constraints

- 缩进 2 空格，expandtab
- CFLAGS 硬编码 `-Wall -Werror`
- 函数前缀 `la_`，类型 `snake_case_t`
- 头文件保护 `_NAME_H_`
- 限速 best-effort，不阻断认证
- libnl 不可用时自动降级（条件编译 `HAVE_LIBNL`）
- `parse_bandwidth` 只接受 Gbps/Mbps/Kbps/bps

---

## File Structure

| 文件 | 责任 |
|------|------|
| `src/la_tc.h` | API 声明 + `rate_limit_config_t` + stub |
| `src/la_tc.c` | HTB qdisc/class/filter + classid 池 + parse_bandwidth |
| `configure.in` | `--enable-tc` + libnl 检测 |
| `src/Makefile.am` | la_tc.c 编译 + libnl 链接 |
| `src/cnf.h/c` | TC 配置字段 + keymaps |
| `src/client_context.h/c` | rate_limit 字段 |
| `src/queue.h/c` | VpnConnGroups rate_limit |
| `src/la_ldap.c/h` | LDAP 限速查询 + 优先级链 + la_tc_reload |
| `src/la_iptables.c` | reload 末尾调用 la_tc_reload |
| `src/ldap-auth.c` | LEARN_ADDRESS hook + 启动/关闭 |
| `tests/test_parse_bandwidth.c` | parse_bandwidth 单元测试 |

---

### Task 1: 构建配置 — libnl 检测

**Files:**
- Modify: `configure.in`
- Modify: `src/Makefile.am`

- [ ] **Step 1: configure.in 添加 --enable-tc**

在 `AC_CHECK_FUNCS([getrlimit])` 之后、`AC_PROG_INSTALL` 之前：

```autoconf
AC_ARG_ENABLE([tc],
  [AS_HELP_STRING([--enable-tc], [Enable TC bandwidth rate limiting (default: auto-detect)])],
  [],
  [enable_tc=auto])

if test "x$enable_tc" != "xno"; then
  PKG_CHECK_MODULES([LIBNL], [libnl-3.0 libnl-route-3.0], [
    have_libnl=yes
    AC_DEFINE(HAVE_LIBNL, 1, [Define if libnl-3 is available])
  ], [
    if test "x$enable_tc" = "xyes"; then
      AC_MSG_ERROR([libnl-3 not found, use --disable-tc])
    fi
    have_libnl=no
  ])
else
  have_libnl=no
fi
AM_CONDITIONAL([HAVE_LIBNL], [test "$have_libnl" = yes])
```

- [ ] **Step 2: configure.in echo 输出**

在 echo 块中 `LDAP user conf` 行之前：
```autoconf
   Traffic control (TC):                              ${have_libnl}
```

- [ ] **Step 3: src/Makefile.am**

`EXTRA_DIST` 之后：
```makefile
libopenvpn_ldap_auth_la_CFLAGS = $(LIBNL_CFLAGS)
libopenvpn_ldap_auth_la_LIBADD = $(LIBNL_LIBS)
```

`auth_ldap_SOURCES` 中 `la_iptables.h la_iptables.c` 之后加 `la_tc.h la_tc.c`。

- [ ] **Step 4: 验证**

Run: `autoreconf -i && ./configure --help | grep enable-tc`
Expected: `--enable-tc` 出现

- [ ] **Step 5: Commit**

```bash
git add configure.in src/Makefile.am
git commit -m "build: add --enable-tc and libnl-3 detection"
```

---

### Task 2: la_tc.h — API 声明

**Files:**
- Create: `src/la_tc.h`

- [ ] **Step 1: 创建 src/la_tc.h**

```c
#ifndef _LA_TC_H_
#define _LA_TC_H_

#include "config.h"
#include <stdint.h>

typedef struct rate_limit_config {
  uint32_t  rate_bps;
} rate_limit_config_t;

extern uint32_t parse_bandwidth(const char *str);

#ifdef HAVE_LIBNL

extern int  la_tc_init(const char *dev, uint32_t global_rate_bps);
extern void la_tc_shutdown(void);
extern int  la_tc_user_add(const char *ip, uint32_t rate_bps);
extern int  la_tc_user_delete(const char *ip);
extern int  la_tc_reload_global(uint32_t new_rate_bps);

#else

static inline int  la_tc_init(const char *d, uint32_t r) { (void)d; (void)r; return 0; }
static inline void la_tc_shutdown(void) {}
static inline int  la_tc_user_add(const char *ip, uint32_t r) { (void)ip; (void)r; return 0; }
static inline int  la_tc_user_delete(const char *ip) { (void)ip; return 0; }
static inline int  la_tc_reload_global(uint32_t r) { (void)r; return 0; }

#endif

#endif
```

- [ ] **Step 2: Commit**

```bash
git add src/la_tc.h
git commit -m "feat(tc): add la_tc.h API header"
```

---

### Task 3: parse_bandwidth + 单元测试

**Files:**
- Create: `src/la_tc.c`
- Create: `tests/test_parse_bandwidth.c`

- [ ] **Step 1: 创建 tests/test_parse_bandwidth.c**

```c
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include "la_tc.h"

int main(void) {
  assert(parse_bandwidth("10Mbps") == 1250000);
  assert(parse_bandwidth("2Mbps") == 250000);
  assert(parse_bandwidth("512Kbps") == 64000);
  assert(parse_bandwidth("100Mbps") == 12500000);
  assert(parse_bandwidth("1Gbps") == 125000000);
  assert(parse_bandwidth("1000bps") == 125);
  assert(parse_bandwidth("10mbps") == 1250000);
  assert(parse_bandwidth(NULL) == 0);
  assert(parse_bandwidth("") == 0);
  assert(parse_bandwidth("1000000") == 0);
  assert(parse_bandwidth("10m") == 0);
  assert(parse_bandwidth("invalid") == 0);
  printf("All parse_bandwidth tests passed.\n");
  return 0;
}
```

- [ ] **Step 2: 创建 src/la_tc.c 骨架 + parse_bandwidth**

```c
#include "config.h"
#include "la_tc.h"
#include "debug.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

uint32_t
parse_bandwidth(const char *str) {
  if (!str || !*str) return 0;
  char unit[8] = {0};
  double value;
  if (sscanf(str, "%lf%7s", &value, unit) < 2) return 0;
  double bps;
  if (!strcasecmp(unit, "bps")) bps = value;
  else if (!strcasecmp(unit, "Kbps")) bps = value * 1000;
  else if (!strcasecmp(unit, "Mbps")) bps = value * 1000000;
  else if (!strcasecmp(unit, "Gbps")) bps = value * 1000000000;
  else return 0;
  return (uint32_t)(bps / 8);
}

#ifdef HAVE_LIBNL

#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/qdisc/htb.h>
#include <netlink/route/class.h>
#include <netlink/route/cls/u32.h>
#include <netlink/route/tc.h>
#include <linux/pkt_sched.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <pthread.h>

#define TC_CLASSID_MIN  100
#define TC_CLASSID_MAX  65534
#define TC_HTB_HANDLE   TC_H_MAKE(1, 0)
#define TC_ROOT_CLASSID TC_H_MAKE(1, 1)

typedef struct ip_classid_map {
  char     ip[46];
  uint32_t classid;
  uint32_t rate_bps;
  struct ip_classid_map *next;
} ip_classid_map_t;

static struct {
  struct nl_sock     *nl_sock;
  int                 tun_ifindex;
  uint32_t            next_classid;
  ip_classid_map_t   *ip_map;
  uint32_t            global_rate_bps;
  int                 initialized;
  pthread_mutex_t     lock;
} g_tc = {0};

static int
create_htb_root(const char *dev, uint32_t rate_bps) {
  g_tc.tun_ifindex = if_nametoindex(dev);
  if (g_tc.tun_ifindex == 0) {
    LOGERROR("la_tc: interface %s not found", dev);
    return -1;
  }
  struct rtnl_qdisc *q = rtnl_qdisc_alloc();
  if (!q) return -1;
  struct rtnl_tc *tc = TC_CAST(q);
  rtnl_tc_set_ifindex(tc, g_tc.tun_ifindex);
  rtnl_tc_set_handle(tc, TC_HTB_HANDLE);
  rtnl_tc_set_kind(tc, "htb");
  rtnl_htb_set_defcls(q, TC_ROOT_CLASSID);
  int err = rtnl_qdisc_add(g_tc.nl_sock, q, NLM_F_CREATE | NLM_F_REPLACE);
  rtnl_qdisc_put(q);
  if (err) { LOGERROR("la_tc: qdisc add failed: %s", nl_geterror(err)); return err; }

  struct rtnl_class *c = rtnl_class_alloc();
  if (!c) return -1;
  tc = TC_CAST(c);
  rtnl_tc_set_ifindex(tc, g_tc.tun_ifindex);
  rtnl_tc_set_kind(tc, "htb");
  rtnl_tc_set_handle(tc, TC_ROOT_CLASSID);
  rtnl_tc_set_parent(tc, TC_HTB_HANDLE);
  rtnl_htb_set_rate(c, rate_bps);
  rtnl_htb_set_ceil(c, rate_bps);
  err = rtnl_class_add(g_tc.nl_sock, c, NLM_F_CREATE | NLM_F_REPLACE);
  rtnl_class_put(c);
  if (err) { LOGERROR("la_tc: root class failed: %s", nl_geterror(err)); return err; }
  return 0;
}

static void
delete_htb_root(void) {
  struct rtnl_qdisc *q = rtnl_qdisc_alloc();
  if (!q) return;
  struct rtnl_tc *tc = TC_CAST(q);
  rtnl_tc_set_ifindex(tc, g_tc.tun_ifindex);
  rtnl_tc_set_handle(tc, TC_HTB_HANDLE);
  rtnl_tc_set_kind(tc, "htb");
  rtnl_qdisc_delete(g_tc.nl_sock, q);
  rtnl_qdisc_put(q);
}

int
la_tc_init(const char *dev, uint32_t global_rate_bps) {
  if (!dev) return -1;
  g_tc.nl_sock = nl_socket_alloc();
  if (!g_tc.nl_sock) { LOGERROR("la_tc: nl_socket_alloc failed"); return -1; }
  int err = nl_connect(g_tc.nl_sock, NETLINK_ROUTE);
  if (err) { LOGERROR("la_tc: nl_connect failed"); nl_socket_free(g_tc.nl_sock); g_tc.nl_sock=NULL; return err; }
  pthread_mutex_init(&g_tc.lock, NULL);
  g_tc.global_rate_bps = global_rate_bps;
  err = create_htb_root(dev, global_rate_bps);
  if (err) { pthread_mutex_destroy(&g_tc.lock); nl_socket_free(g_tc.nl_sock); g_tc.nl_sock=NULL; return err; }
  g_tc.next_classid = TC_CLASSID_MIN;
  g_tc.ip_map = NULL;
  g_tc.initialized = 1;
  LOGNOTICE("la_tc: enabled on %s, global=%u B/s", dev, global_rate_bps);
  return 0;
}

void
la_tc_shutdown(void) {
  if (!g_tc.initialized) return;
  pthread_mutex_lock(&g_tc.lock);
  delete_htb_root();
  ip_classid_map_t *cur = g_tc.ip_map;
  while (cur) { ip_classid_map_t *next = cur->next; la_free(cur); cur = next; }
  g_tc.ip_map = NULL;
  if (g_tc.nl_sock) { nl_socket_free(g_tc.nl_sock); g_tc.nl_sock = NULL; }
  g_tc.initialized = 0;
  pthread_mutex_unlock(&g_tc.lock);
  pthread_mutex_destroy(&g_tc.lock);
  LOGINFO("la_tc: shutdown");
}

int
la_tc_user_add(const char *ip, uint32_t rate_bps) {
  if (!g_tc.initialized || !ip) return 0;
  if (!rate_bps) rate_bps = g_tc.global_rate_bps;
  if (!rate_bps) return 0;

  pthread_mutex_lock(&g_tc.lock);

  ip_classid_map_t *cur = g_tc.ip_map;
  while (cur) {
    if (strcmp(cur->ip, ip) == 0) {
      if (cur->rate_bps == rate_bps) { pthread_mutex_unlock(&g_tc.lock); return 0; }
      struct rtnl_class *c = rtnl_class_alloc();
      if (c) {
        struct rtnl_tc *tc = TC_CAST(c);
        rtnl_tc_set_ifindex(tc, g_tc.tun_ifindex);
        rtnl_tc_set_kind(tc, "htb");
        rtnl_tc_set_handle(tc, TC_H_MAKE(1, cur->classid));
        rtnl_tc_set_parent(tc, TC_ROOT_CLASSID);
        rtnl_htb_set_rate(c, rate_bps);
        rtnl_htb_set_ceil(c, rate_bps);
        rtnl_class_add(g_tc.nl_sock, c, NLM_F_REPLACE);
        rtnl_class_put(c);
        cur->rate_bps = rate_bps;
      }
      pthread_mutex_unlock(&g_tc.lock);
      LOGINFO("la_tc: %s updated rate=%u", ip, rate_bps);
      return 0;
    }
    cur = cur->next;
  }

  if (g_tc.next_classid > TC_CLASSID_MAX) {
    LOGERROR("la_tc: classid exhausted for %s", ip);
    pthread_mutex_unlock(&g_tc.lock);
    return -1;
  }
  uint32_t classid = g_tc.next_classid++;

  struct in_addr addr;
  if (inet_pton(AF_INET, ip, &addr) != 1) {
    pthread_mutex_unlock(&g_tc.lock);
    return -1;
  }

  struct rtnl_class *c = rtnl_class_alloc();
  if (!c) { pthread_mutex_unlock(&g_tc.lock); return -1; }
  struct rtnl_tc *tc = TC_CAST(c);
  rtnl_tc_set_ifindex(tc, g_tc.tun_ifindex);
  rtnl_tc_set_kind(tc, "htb");
  rtnl_tc_set_handle(tc, TC_H_MAKE(1, classid));
  rtnl_tc_set_parent(tc, TC_ROOT_CLASSID);
  rtnl_htb_set_rate(c, rate_bps);
  rtnl_htb_set_ceil(c, rate_bps);
  int err = rtnl_class_add(g_tc.nl_sock, c, NLM_F_CREATE);
  rtnl_class_put(c);
  if (err) { LOGERROR("la_tc: class add failed: %s", nl_geterror(err)); pthread_mutex_unlock(&g_tc.lock); return err; }

  struct rtnl_cls *cls = rtnl_cls_alloc();
  if (cls) {
    tc = TC_CAST(cls);
    rtnl_tc_set_ifindex(tc, g_tc.tun_ifindex);
    rtnl_tc_set_handle(tc, TC_H_MAKE(1, classid));
    rtnl_tc_set_parent(tc, TC_HTB_HANDLE);
    rtnl_tc_set_kind(tc, "u32");
    rtnl_u32_add_key(cls, ntohl(addr.s_addr), 0xFFFFFFFF, 0, 0);
    rtnl_u32_set_classid(cls, TC_H_MAKE(1, classid));
    rtnl_cls_add(g_tc.nl_sock, cls, NLM_F_CREATE);
    rtnl_cls_put(cls);
  }

  ip_classid_map_t *entry = la_malloc(sizeof(ip_classid_map_t));
  if (entry) {
    strncpy(entry->ip, ip, sizeof(entry->ip)-1);
    entry->ip[sizeof(entry->ip)-1] = '\0';
    entry->classid = classid;
    entry->rate_bps = rate_bps;
    entry->next = g_tc.ip_map;
    g_tc.ip_map = entry;
  }

  pthread_mutex_unlock(&g_tc.lock);
  LOGINFO("la_tc: %s -> classid %u rate=%u", ip, classid, rate_bps);
  return 0;
}

int
la_tc_user_delete(const char *ip) {
  if (!g_tc.initialized || !ip) return 0;
  pthread_mutex_lock(&g_tc.lock);
  ip_classid_map_t **pp = &g_tc.ip_map;
  while (*pp) {
    if (strcmp((*pp)->ip, ip) == 0) {
      ip_classid_map_t *entry = *pp;
      uint32_t classid = entry->classid;
      *pp = entry->next;
      la_free(entry);
      struct rtnl_class *c = rtnl_class_alloc();
      if (c) {
        struct rtnl_tc *tc = TC_CAST(c);
        rtnl_tc_set_ifindex(tc, g_tc.tun_ifindex);
        rtnl_tc_set_kind(tc, "htb");
        rtnl_tc_set_handle(tc, TC_H_MAKE(1, classid));
        rtnl_class_delete(g_tc.nl_sock, c);
        rtnl_class_put(c);
      }
      pthread_mutex_unlock(&g_tc.lock);
      LOGINFO("la_tc: %s removed (classid %u)", ip, classid);
      return 0;
    }
    pp = &(*pp)->next;
  }
  pthread_mutex_unlock(&g_tc.lock);
  return 0;
}

int
la_tc_reload_global(uint32_t new_rate_bps) {
  if (!g_tc.initialized) return 0;
  pthread_mutex_lock(&g_tc.lock);
  g_tc.global_rate_bps = new_rate_bps;
  struct rtnl_class *c = rtnl_class_alloc();
  if (!c) { pthread_mutex_unlock(&g_tc.lock); return -1; }
  struct rtnl_tc *tc = TC_CAST(c);
  rtnl_tc_set_ifindex(tc, g_tc.tun_ifindex);
  rtnl_tc_set_kind(tc, "htb");
  rtnl_tc_set_handle(tc, TC_ROOT_CLASSID);
  rtnl_tc_set_parent(tc, TC_HTB_HANDLE);
  rtnl_htb_set_rate(c, new_rate_bps);
  rtnl_htb_set_ceil(c, new_rate_bps);
  int err = rtnl_class_add(g_tc.nl_sock, c, NLM_F_REPLACE);
  rtnl_class_put(c);
  pthread_mutex_unlock(&g_tc.lock);
  LOGINFO("la_tc: global rate reloaded=%u", new_rate_bps);
  return err;
}

#endif
```

- [ ] **Step 3: 编译测试**

Run: `gcc -Wall -Werror -Isrc -I. -D_GNU_SOURCE -DHAVE_CONFIG_H tests/test_parse_bandwidth.c src/la_tc.c -o /tmp/test_pb && /tmp/test_pb`
Expected: `All parse_bandwidth tests passed.`

- [ ] **Step 4: Commit**

```bash
git add src/la_tc.c src/la_tc.h tests/test_parse_bandwidth.c
git commit -m "feat(tc): implement la_tc with HTB qdisc and parse_bandwidth"
```

---

### Task 4: 配置结构 + keymaps

**Files:**
- Modify: `src/cnf.h`
- Modify: `src/cnf.c`

- [ ] **Step 1: cnf.h 添加 TC 字段**

profile_config_t 中 `iptable_rules_field` 之后：
```c
  /* TC rate limiting */
  ternary_t   tc_enabled;
  char        *tc_global_rate;
  char        *tc_user_rate_attr;
  char        *tc_group_rate_attr;
```

cnf.h 底部 extern 区：
```c
extern ldap_config_keyvalue_t *tc_limit_config;
extern ldap_config_keyvalue_t *tc_group_limit_rules;
```

- [ ] **Step 2: cnf.c 全局变量**

`ldapconfig = NULL;` 之后：
```c
ldap_config_keyvalue_t *tc_limit_config = NULL;
ldap_config_keyvalue_t *tc_group_limit_rules = NULL;
```

- [ ] **Step 3: cnf.c free/init/dup/parse/dump**

参照现有 iptable_rules_field 模式，为 tc_enabled/tc_global_rate/tc_user_rate_attr/tc_group_rate_attr 添加 free/init/dup。

config_parse_file 中添加 tc_limit_config 循环 + tc_group_limit_rules 循环。

config_init_ldap_config_set 中添加 tc_limit/tc_group_limit_rate keylayer==1 段切换 + keylayer==2 嵌套切换。

- [ ] **Step 4: 编译验证**

Run: `make -j4 2>&1 | grep error`
Expected: 无

- [ ] **Step 5: Commit**

```bash
git add src/cnf.h src/cnf.c
git commit -m "feat(tc): add TC config fields and YAML parsing"
```

---

### Task 5: client_context + queue

**Files:**
- Modify: `src/client_context.h`, `src/client_context.c`
- Modify: `src/queue.h`, `src/queue.c`

- [ ] **Step 1: client_context.h**

顶部加 `#include "la_tc.h"`（在 `#include "cnf.h"` 之后）。

client_context_t 中 `groups` 之后加：
```c
  rate_limit_config_t *rate_limit;
```

- [ ] **Step 2: client_context.c**

free 函数中 groups 释放之后加：
```c
  FREE_IF_NOT_NULL (cc->rate_limit);
```

- [ ] **Step 3: queue.h**

顶部加 `#include "la_tc.h"`。

VpnConnGroups 结构体加：
```c
    rate_limit_config_t *rate_limit;
```

- [ ] **Step 4: queue.c**

FreeConnVPNDataMem 中 description 释放后加：
```c
        check_and_free(vpndata->groups[i].rate_limit);
```

- [ ] **Step 5: Commit**

```bash
git add src/client_context.h src/client_context.c src/queue.h src/queue.c
git commit -m "feat(tc): add rate_limit to client_context and VpnConnGroups"
```

---

### Task 6: LDAP 限速查询 + 优先级链

**Files:**
- Modify: `src/la_ldap.c`, `src/la_ldap.h`

- [ ] **Step 1: la_ldap.c include**

`#include "config.h"` 之后加 `#include "la_tc.h"`

- [ ] **Step 2: ldap_group_membership 中查组限速属性**

attrs 数组加 `tc_group_rate_attr`。属性遍历中检测 `tc_group_rate_attr`，存入 `cc->groups[group_num].rate_limit`。

- [ ] **Step 3: la_ldap_handle_authentication 中查用户限速 + 优先级链**

认证成功后、组过滤后，查 LDAP 用户 `tc_user_rate_attr` 属性。

优先级链 resolve：
1. LDAP 组 (groups[].rate_limit)
2. LDAP 用户 (cc->rate_limit)
3. YAML 组 (group_rate_limits[])
4. YAML 全局 (tc_global_rate)

存入 `cc->rate_limit`。

- [ ] **Step 4: la_tc_reload + la_tc_reload_yaml**

`la_tc_reload`：只调 `la_tc_reload_global`，不遍历队列。
`la_tc_reload_yaml`：重解析 YAML 更新 profile TC 字段。

la_ldap.h 声明这两个函数。

- [ ] **Step 5: config_load_ldap_groups_profiles**

attrs 加 `tc_group_rate_attr`。属性遍历中填充 `ldap_group_rate_limits[]`。

- [ ] **Step 6: 编译验证 + Commit**

```bash
git add src/la_ldap.c src/la_ldap.h
git commit -m "feat(tc): LDAP rate query + priority chain + reload"
```

---

### Task 7: ldap-auth.c hook + la_iptables.c

**Files:**
- Modify: `src/ldap-auth.c`
- Modify: `src/la_iptables.c`

- [ ] **Step 1: ldap-auth.c include**

`#include "la_iptables.h"` 之后加 `#include "la_tc.h"`

- [ ] **Step 2: openvpn_plugin_open_v2 TC 初始化**

`la_iptables_start_monitor` 之后：
```c
  if( pro_fd->tc_enabled == TERN_TRUE ){
    uint32_t rate = 0;
    if( pro_fd->tc_global_rate )
      rate = parse_bandwidth( pro_fd->tc_global_rate );
    if( la_tc_init( openvpnserverinfo->dev, rate ) != 0 )
      pro_fd->tc_enabled = TERN_FALSE;
  }
```

- [ ] **Step 3: LEARN_ADDRESS add/delete/update**

add: `la_learn_roles_add` 之后加 `la_tc_user_add(ip, cc->rate_limit->rate_bps)`
delete: `la_learn_roles_delete` 之前加 `la_tc_user_delete(ip)`
update: 先 delete old_ip，后 add new_ip

不加 action_mutex（保持无阻塞）。

- [ ] **Step 4: openvpn_plugin_close_v1**

`la_iptables_stop_monitor` 之后加 `la_tc_shutdown()`

- [ ] **Step 5: la_iptables.c reload**

`config_iptables_printf` 之后、`pthread_mutex_unlock` 之前：
```c
    la_tc_reload_yaml(l);
    la_tc_reload(l);
```

- [ ] **Step 6: 编译验证 + Commit**

```bash
git add src/ldap-auth.c src/la_iptables.c
git commit -m "feat(tc): integrate TC hooks into OpenVPN plugin lifecycle"
```

---

### Task 8: 配置样例 + README

**Files:**
- Modify: `tests/config.conf`
- Modify: `README`

- [ ] **Step 1: config.conf**

IPTABLERULES 段之后添加：
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

- [ ] **Step 2: README**

Dependencies 加 `libnl-3, libnl-route-3`。
功能说明加 TC 限速。
配置样例同步。

- [ ] **Step 3: Commit**

```bash
git add tests/config.conf README
git commit -m "docs: add TC config samples"
```

---

### Task 9: 集成验证

- [ ] **Step 1: 完整构建**

Run: `autoreconf -i && ./configure && make`
Expected: 无错误

- [ ] **Step 2: parse_bandwidth 测试**

Run: `./tests/test_parse_bandwidth`
Expected: `All parse_bandwidth tests passed.`

- [ ] **Step 3: --enable-tc / --disable-tc**

Run: `./configure --enable-tc 2>&1 | grep "Traffic"` (Linux 有 libnl 时 yes)
Run: `./configure --disable-tc 2>&1 | grep "Traffic"` (应该 no)

- [ ] **Step 4: Commit (if any adjustments)**

```bash
git add -A
git commit -m "test(tc): integration verified"
```
