/**
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 * cnf.h
 *
 * Copyright (C) 2009 Emmanuel Bretelle <chantra@debuntu.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _CNF_H_
#define _CNF_H_

#include "list.h"
#include "types.h"
#include "config.h"

#include <sys/types.h>

#define  IP_RULE_KEYS_BUF   128
#define  IP_RULE_ITEM_BUF   256

typedef struct ip_perm_rules {
    u_int   vlen;
    char    *name;
    char    *value[IP_RULE_ITEM_BUF];
} rules_item_t;

typedef struct ip_perm {
  u_int         klen;
  rules_item_t  items[IP_RULE_KEYS_BUF];
} ip_perm_rules_t ;

typedef struct ldap_conf_t
{
  u_int len;
  struct ldap_keymap_t {
    char  *name;
    char  *value;
  } keymaps[IP_RULE_KEYS_BUF];
} ldap_config_keyvalue_t;

ip_perm_rules_t *iptblrules;
ldap_config_keyvalue_t *ldapconfig;


typedef enum ldap_search_scope{
  LA_SCOPE_BASE = 0,
  LA_SCOPE_ONELEVEL,
  LA_SCOPE_SUBTREE
} ldap_search_scope_t;
/**
 * ldap_config
 * defines how to connect to an ldap server
 */

typedef struct ldap_config{
  char			*uri;

  char			*binddn;
  char			*bindpw;

  int				version;
  int       timeout;

  /* TLS/SSL */
  char			*ssl;
  char			*tls_cacertfile;
  char			*tls_cacertdir;
  char			*tls_certfile;
  char			*tls_certkey;
  char			*tls_ciphersuite;
  char			*tls_reqcert;


} ldap_config_t;

typedef struct profile_config{
  char        *basedn;
  char        *search_filter;
  ldap_search_scope_t search_scope;
  /* group membership */
  char        *groupdn;
  char        *group_search_filter;
  char        *member_attribute;
  /* default gw hack */
  char        *redirect_gateway_prefix;
  char        *redirect_gateway_flags;
  /* packet filtering */
  ternary_t    enable_pf;
  char        *default_pf_rules;
#ifdef ENABLE_LDAPUSERCONF
  /* default profiledn for ldap user conf */
  char        *default_profiledn;
#endif
} profile_config_t;

/**
 * config hold a reference to global_config
 * and the different profiles to use
 */
typedef struct config{
  ldap_config_t    *ldap;
  list_t    *profiles;
} config_t;

extern int config_parse_file( const char *filename, config_t *c );

extern config_t *config_new( void );
extern config_t *config_dup( config_t *c );
extern void config_free( config_t *c );
extern void config_dump( config_t *c );
extern void config_set_default( config_t *c );
extern int config_is_pf_enabled( config_t *c );
extern int config_is_pf_enabled_for_profile( profile_config_t *p );
extern int config_is_redirect_gw_enabled( config_t *c );
extern int config_is_redirect_gw_enabled_for_profile( profile_config_t *p );

// yaml config 
extern int  config_parse_file_new( config_t *c );
extern void printf_ldap_config(ldap_config_keyvalue_t *lc);
extern void printf_iptables_config(ip_perm_rules_t *iprules);
extern void config_free_iptable_rule(struct ip_perm *rules);
extern void config_free_ldap(ldap_config_keyvalue_t *ldapconf);
extern void config_init_iptable_rule(struct ip_perm *rules);
extern void config_generate_ldap_keyvalue_t(char *key, char *val,u_int i );
extern int  config_init_ldap_iptable(const char *filename,int verb);

#endif /* _CNF_H_ */
