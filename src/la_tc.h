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

#include <stdint.h>

/* 带宽限速配置（字节/秒） */
typedef struct rate_limit_config {
  uint32_t  rate_bps;    /* 保证速率 */
  uint32_t  ceil_bps;    /* 最大速率 */
} rate_limit_config_t;

/**
 * 解析带宽字符串为字节/秒。
 * 支持格式: "10Mbps", "512Kbps", "1Gbps", "1000000" (bps)
 * 返回: 字节/秒，解析失败返回 0
 */
extern uint32_t parse_bandwidth(const char *str);

#ifdef HAVE_LIBNL

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

#else /* !HAVE_LIBNL */

/* 无 libnl 时的 no-op stub */
static inline int  la_tc_init(const char *tun_dev, rate_limit_config_t *global) {
  (void)tun_dev; (void)global; return 0;
}
static inline void la_tc_shutdown(void) {}
static inline int  la_tc_user_add(const char *client_ip, rate_limit_config_t *user_rl) {
  (void)client_ip; (void)user_rl; return 0;
}
static inline int  la_tc_user_delete(const char *client_ip) {
  (void)client_ip; return 0;
}
static inline int  la_tc_reload_global(rate_limit_config_t *new_global) {
  (void)new_global; return 0;
}

#endif /* HAVE_LIBNL */

#endif /* _LA_TC_H_ */
