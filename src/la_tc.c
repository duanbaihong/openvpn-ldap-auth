/**
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 * la_tc.c
 * Traffic control (HTB qdisc) based per-user bandwidth limiting.
 * Uses libnl-3 / libnl-route-3 rtnetlink API when available.
 */
#include "config.h"

#include "la_tc.h"
#include "debug.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

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

  matched = sscanf(str, "%lf%7s", &value, unit);
  if (matched < 1) return 0;

  double bps;
  if (matched == 1) {
    bps = value;
  } else {
    if (!strcasecmp(unit, "bps")) {
      bps = value;
    } else if (!strcasecmp(unit, "kbps") || !strcasecmp(unit, "k")) {
      bps = value * 1000;
    } else if (!strcasecmp(unit, "mbps") || !strcasecmp(unit, "m")) {
      bps = value * 1000000;
    } else if (!strcasecmp(unit, "gbps") || !strcasecmp(unit, "g")) {
      bps = value * 1000000000;
    } else {
      return 0;
    }
  }

  return (uint32_t)(bps / 8);
}

#ifdef HAVE_LIBNL

#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/qdisc/htb.h>
#include <netlink/route/class.h>
#include <netlink/route/tc.h>
#include <linux/pkt_sched.h>
#include <arpa/inet.h>
#include <net/if.h>

#define TC_CLASSID_MIN    100
#define TC_CLASSID_MAX    65534
#define TC_HTB_HANDLE     TC_H_MAKE(1, 0)
#define TC_ROOT_CLASSID   TC_H_MAKE(1, 1)

typedef struct ip_classid_map {
  char     ip[46];
  uint32_t classid;
  struct ip_classid_map *next;
} ip_classid_map_t;

static struct {
  struct nl_sock     *nl_sock;
  int                 tun_ifindex;
  uint32_t            next_classid;
  ip_classid_map_t   *ip_map;
  rate_limit_config_t global_rl;
  int                 initialized;
} g_tc = {0};

static int
create_htb_root(const char *tun_dev, rate_limit_config_t *global) {
  struct rtnl_qdisc *qdisc;
  struct rtnl_class *rclass;
  struct rtnl_tc *tc;
  int err;

  g_tc.tun_ifindex = if_nametoindex(tun_dev);
  if (g_tc.tun_ifindex == 0) {
    LOGERROR("la_tc: interface %s not found: %s", tun_dev, strerror(errno));
    return -1;
  }

  qdisc = rtnl_qdisc_alloc();
  if (!qdisc) return -1;
  tc = TC_CAST(qdisc);
  rtnl_tc_set_ifindex(tc, g_tc.tun_ifindex);
  rtnl_tc_set_handle(tc, TC_HTB_HANDLE);
  rtnl_tc_set_kind(tc, "htb");
  rtnl_htb_set_defcls(qdisc, TC_ROOT_CLASSID);
  rtnl_htb_set_rate2quantum(qdisc, 1);
  err = rtnl_qdisc_add(g_tc.nl_sock, qdisc, NLM_F_CREATE | NLM_F_REPLACE);
  rtnl_qdisc_put(qdisc);
  if (err != 0) {
    LOGERROR("la_tc: failed to create HTB root qdisc: %s", nl_geterror(err));
    return err;
  }

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

static uint32_t
alloc_classid(void) {
  if (g_tc.next_classid > TC_CLASSID_MAX) {
    return 0;
  }
  return g_tc.next_classid++;
}

static uint32_t
lookup_classid(const char *ip) {
  ip_classid_map_t *cur = g_tc.ip_map;
  while (cur) {
    if (strcmp(cur->ip, ip) == 0) return cur->classid;
    cur = cur->next;
  }
  return 0;
}

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

static int
add_ip_filter(uint32_t src_ip_n, uint32_t classid) {
  struct rtnl_cls *cls;
  struct rtnl_tc *tc;
  int err;
  uint32_t mask = 0xFFFFFFFF;

  cls = rtnl_cls_alloc();
  if (!cls) return -1;
  tc = TC_CAST(cls);
  rtnl_tc_set_ifindex(tc, g_tc.tun_ifindex);
  rtnl_tc_set_handle(tc, TC_H_MAKE(1, classid));
  rtnl_tc_set_parent(tc, TC_HTB_HANDLE);
  rtnl_tc_set_kind(tc, "u32");

  rtnl_u32_add_key(cls, &src_ip_n, &mask, sizeof(src_ip_n), 0);
  rtnl_u32_set_classid(cls, TC_H_MAKE(1, classid));

  err = rtnl_cls_add(g_tc.nl_sock, cls, NLM_F_CREATE);
  rtnl_cls_put(cls);
  if (err != 0) {
    LOGERROR("la_tc: add_ip_filter(%u) failed: %s", classid, nl_geterror(err));
  }
  return err;
}

int
la_tc_init(const char *tun_dev, rate_limit_config_t *global) {
  int err;

  if (!tun_dev) {
    LOGERROR("la_tc_init: tun_dev is NULL");
    return -1;
  }

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

  if (global) {
    g_tc.global_rl = *global;
  } else {
    memset(&g_tc.global_rl, 0, sizeof(g_tc.global_rl));
  }

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

  delete_htb_root();

  ip_classid_map_t *cur = g_tc.ip_map;
  while (cur) {
    ip_classid_map_t *next = cur->next;
    la_free(cur);
    cur = next;
  }
  g_tc.ip_map = NULL;

  if (g_tc.nl_sock) {
    nl_socket_free(g_tc.nl_sock);
    g_tc.nl_sock = NULL;
  }

  g_tc.initialized = 0;
  LOGINFO("la_tc: shutdown complete");
}

int
la_tc_user_add(const char *client_ip, rate_limit_config_t *user_rl) {
  if (!g_tc.initialized || !g_tc.nl_sock) {
    LOGDEBUG("la_tc: not initialized, skipping user_add");
    return 0;
  }
  if (!client_ip) {
    LOGERROR("la_tc_user_add: client_ip is NULL");
    return -1;
  }

  uint32_t existing = lookup_classid(client_ip);
  if (existing) {
    LOGWARNING("la_tc: IP %s already has classid %u, deleting old", client_ip, existing);
    delete_user_class(existing);
    remove_ip_mapping(client_ip);
  }

  uint32_t classid = alloc_classid();
  if (classid == 0) {
    LOGERROR("la_tc: classid exhausted, user %s falls back to root class", client_ip);
    return -1;
  }

  uint32_t rate = (user_rl && user_rl->rate_bps) ? user_rl->rate_bps : g_tc.global_rl.rate_bps;
  uint32_t ceil = (user_rl && user_rl->ceil_bps) ? user_rl->ceil_bps : g_tc.global_rl.ceil_bps;
  if (rate == 0) {
    LOGDEBUG("la_tc: no rate configured for %s, using global or skipping", client_ip);
    return 0;
  }

  struct in_addr addr;
  if (inet_pton(AF_INET, client_ip, &addr) != 1) {
    LOGERROR("la_tc: invalid IP %s", client_ip);
    return -1;
  }

  int err = create_user_class(classid, rate, ceil);
  if (err != 0) {
    return err;
  }

  err = add_ip_filter(addr.s_addr, classid);
  if (err != 0) {
    delete_user_class(classid);
    return err;
  }

  if (add_ip_mapping(client_ip, classid) != 0) {
    delete_user_class(classid);
    return -1;
  }

  LOGINFO("la_tc: user %s -> classid %u (rate=%u, ceil=%u)", client_ip, classid, rate, ceil);
  return 0;
}

int
la_tc_user_delete(const char *client_ip) {
  if (!g_tc.initialized || !client_ip) return 0;

  uint32_t classid = remove_ip_mapping(client_ip);
  if (classid == 0) {
    LOGDEBUG("la_tc: IP %s not found in mapping, skip delete", client_ip);
    return 0;
  }

  delete_user_class(classid);
  LOGINFO("la_tc: user %s removed (classid %u)", client_ip, classid);
  return 0;
}

int
la_tc_reload_global(rate_limit_config_t *new_global) {
  if (!g_tc.initialized) return 0;

  if (new_global) {
    g_tc.global_rl = *new_global;
  }

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

  LOGINFO("la_tc: global rate reloaded (rate=%u, ceil=%u)",
          g_tc.global_rl.rate_bps, g_tc.global_rl.ceil_bps);
  return err;
}

#endif /* HAVE_LIBNL */
