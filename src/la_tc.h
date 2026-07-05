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
