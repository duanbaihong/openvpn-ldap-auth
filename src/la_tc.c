#include "config.h"
#include "la_tc.h"
#include "debug.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
  LOGNOTICE("la_tc: HTB root on %s ifindex=%d rate=%u", dev, g_tc.tun_ifindex, rate_bps);
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
