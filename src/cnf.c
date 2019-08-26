/**
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 * cnf.c
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

#include "cnf.h"
#include "utils.h"
#include "defines.h"
#include "debug.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>  /* isspace */

#include "yaml.h"
#include <stdbool.h>

#define LOGDEBUG_IFSET(a,prefix) if(a) LOGDEBUG( "%s: %s", prefix, a);
#define STRDUP_IFNOTSET(a,b) if(!a && b) a=strdup(b);
#define CHECK_IF_IN_PROFILE(a,b) if(!b){ \
LOGWARNING("%s is not defined within <profile></profile>. It will be ignored", a);\
free( line );\
continue;\
}


//#define STRDUP_IFNOTSET_NOTNULL(a, b) if( b ) STRDUP_IFNOTSET(a,b)

void
config_set_default( config_t *c){
#ifdef OURI
  if(OURI) STRDUP_IFNOTSET(c->ldap->uri, OURI );
#endif
#ifdef OBINDDN
  STRDUP_IFNOTSET(c->ldap->binddn, OBINDDN );
#endif
#ifdef OBINDPW
  STRDUP_IFNOTSET(c->ldap->bindpw, OBINDPW);
#endif
  if(!c->ldap->version) c->ldap->version =  OLDAP_VERSION;
#ifdef OSSL
  STRDUP_IFNOTSET(c->ldap->ssl, OSSL );
#endif
#ifdef OTLS_CACERTFILE
  STRDUP_IFNOTSET(c->ldap->tls_cacertfile, OTLS_CACERTFILE );
#endif
#ifdef OTLS_CACERTDIR
  STRDUP_IFNOTSET(c->ldap->tls_cacertdir, OTLS_CACERTDIR );
#endif
#ifdef OTLS_CERTFILE
  STRDUP_IFNOTSET(c->ldap->tls_certfile, OTLS_CERTFILE );
#endif
#ifdef OTLS_CERTKEY
  STRDUP_IFNOTSET(c->ldap->tls_certkey, OTLS_CERTKEY );
#endif
#ifdef OTLS_CIPHERSUITE
  STRDUP_IFNOTSET(c->ldap->tls_ciphersuite, OTLS_CIPHERSUITE );
#endif
#ifdef OTLS_REQCERT
  STRDUP_IFNOTSET(c->ldap->tls_reqcert, OTLS_REQCERT );
#endif
#ifdef OTIMEOUT
  if( !c->ldap->timeout ) c->ldap->timeout = OTIMEOUT;
#endif

// 设置默认值
if(!openvpnserverinfo->verb) openvpnserverinfo->verb=0;
STRDUP_IFNOTSET(openvpnserverinfo->serverport,"1194");
STRDUP_IFNOTSET(openvpnserverinfo->listenip,"0.0.0.0");
STRDUP_IFNOTSET(openvpnserverinfo->serverip,"172.16.0.0");
STRDUP_IFNOTSET(openvpnserverinfo->proto,"udp");
STRDUP_IFNOTSET(openvpnserverinfo->netmask,"255.255.255.0");
STRDUP_IFNOTSET(openvpnserverinfo->netaddr,GetNetworkAndCIDRAddress(openvpnserverinfo->serverip,openvpnserverinfo->netmask));

}

/**
 * ldap config
 */
void
ldap_config_free( ldap_config_t *c ){
  check_and_free( c->uri );
  check_and_free( c->binddn );
  check_and_free( c->bindpw );
  /* TLS */
  check_and_free( c->ssl );
  check_and_free( c->tls_cacertfile );
  check_and_free( c->tls_cacertdir );
  check_and_free( c->tls_certfile );
  check_and_free( c->tls_certkey );
  check_and_free( c->tls_ciphersuite );
  check_and_free( c->tls_reqcert );
  la_free( c );
}

ldap_config_t *
ldap_config_new( void ){
  ldap_config_t *c = la_malloc( sizeof( ldap_config_t ) );
  if( !c ) return NULL;
  la_memset (c, 0, sizeof( ldap_config_t ) );
  return c;
}

ldap_config_t *
ldap_config_dup( const ldap_config_t *c ){
  ldap_config_t *nc = ldap_config_new( );
  if( !nc)
      return NULL;

  if( c->uri ) nc->uri = strdup( c->uri );
  if( c->binddn ) nc->binddn = strdup( c->binddn );
  if( c->bindpw ) nc->bindpw = strdup( c->bindpw );
  nc->version = c->version;
  if( c->ssl ) nc->ssl = strdup( c->ssl );
  if( c->tls_cacertfile ) nc->tls_cacertfile = strdup( c->tls_cacertfile );
  if( c->tls_cacertdir ) nc->tls_cacertdir = strdup( c->tls_cacertdir );
  if( c->tls_certfile ) nc->tls_certfile = strdup( c->tls_certfile );
  if( c->tls_certkey ) nc->tls_certkey = strdup( c->tls_certkey );
  if( c->tls_ciphersuite ) nc->tls_ciphersuite = strdup( c->tls_ciphersuite );
  if( c->tls_reqcert ) nc->tls_reqcert = strdup( c->tls_reqcert );

  nc->timeout = c->timeout;

  return nc;
}

/**
 * profile
 */
void
profile_config_free ( profile_config_t *c ){
  if( !c )
    return;

	check_and_free( c->usersdn );
  check_and_free( c->search_filter );
  /* Group */
  check_and_free( c->groupdn );
  check_and_free( c->group_search_filter );
  check_and_free( c->member_attribute );
  check_and_free( c->default_pf_rules );
  for(int i=0;c->group_map_field[i]!=NULL;i++)
  {
    check_and_free( c->group_map_field[i] );
  }
  /* redirect gateway */
  check_and_free( c->redirect_gateway_prefix );
  check_and_free( c->redirect_gateway_flags );
#ifdef ENABLE_LDAPUSERCONF
  check_and_free( c->default_profiledn );
#endif
	la_free( c );
}

void
profile_config_list_free_cb( void *data ){
  profile_config_t *c = data;
  profile_config_free( c );
}

profile_config_t *
profile_config_new ( void ){
  profile_config_t *c = la_malloc( sizeof( profile_config_t ) );
  if( !c ) return NULL;
  la_memset (c, 0, sizeof( profile_config_t ) );
  c->search_scope = LA_SCOPE_ONELEVEL;
  return c;
}

profile_config_t *
profile_config_dup( const profile_config_t *c ){
  profile_config_t *nc = NULL;

  nc = profile_config_new( );
  if( nc == NULL )
    return NULL;

  if( c->usersdn ) nc->usersdn = strdup( c->usersdn );
  if( c->search_filter ) nc->search_filter = strdup( c->search_filter );
  nc->search_scope = c->search_scope;
  /* Group */
  if( c->groupdn ) nc->groupdn = strdup( c->groupdn );
  if( c->group_search_filter ) nc->group_search_filter = strdup( c->group_search_filter );
  if( c->member_attribute ) nc->member_attribute = strdup( c->member_attribute );
  /* PF */
  if( c->default_pf_rules ) nc->default_pf_rules = strdup( c->default_pf_rules );
  nc->enable_pf = c->enable_pf;
  /* default gw */
  if( c->redirect_gateway_prefix ) nc->redirect_gateway_prefix = strdup( c->redirect_gateway_prefix );
  if( c->redirect_gateway_flags ) nc->redirect_gateway_flags = strdup( c->redirect_gateway_flags );
#ifdef ENABLE_LDAPUSERCONF
  if( c->default_profiledn ) nc->default_profiledn = strdup( c->default_profiledn );
#endif

  return nc;
}

/**
 * config
 */
config_t *
config_new( void ){
	config_t *c = malloc( sizeof( config_t ) );
	if( !c ) return NULL;
	memset( c, 0, sizeof( config_t ) );

  c->ldap = ldap_config_new( );
  c->profiles = list_new( );

  if( !(c->profiles && c->ldap) ){
    config_free( c );
    return NULL;
  }
	return c;
}

config_t *
config_dup( config_t *c ){
  config_t *nc = NULL;
  profile_config_t *pgc = NULL;
  list_item_t *item = NULL;
  ldap_config_t *l = NULL;

  if( !c ) return NULL;
  nc = config_new( );
  if( !nc ) return NULL;
  /* ldap */
  l = ldap_config_dup( c->ldap );
  ldap_config_free( nc->ldap );
  nc->ldap = l;

  /* profiles */
  for( item = list_first(c->profiles); item; item = item->next ){
    pgc = profile_config_dup( item->data );
    list_append( nc->profiles, pgc );
  }

  return nc;
}


void
config_free( config_t *c ){
	if( !c ) return;
  ldap_config_free( c->ldap );
  list_free( c->profiles, profile_config_list_free_cb );
  la_free( c );
}

char *
f_readline( int fd ){
	char *line = NULL;
	int length = 0;
	char c;
	int rc = 0;
	while( ( rc = read( fd, &c, 1 ) ) > 0 ){
		length++;
		line = realloc( line, length + 1 );
		line[length-1] = c;
		if( c == '\n' ) break;
	}
	if( rc < 0 ){
		/* an error occured */
		free(line);
		return NULL;
	}
	if(line) line[length] = '\0';
	return line;
}


char *
skip_whitespaces( char *l ){
  while(isspace(l[0]))
    l++;
  return l;
}

int
config_parse_file( const char *filename, config_t *c ){
	int fd;
	char *line;
  char *arg,*val;
  int in_profile = 0;
  int rc = 0;
  profile_config_t *p = NULL;
	fd = open( filename, O_RDONLY );
	if( fd == -1 ){
    LOGERROR( "Could not open file %s: (%d) %s", filename, errno, strerror( errno ) );
		return 1;
	}
  val = NULL;
	while ( ( line = f_readline( fd ) ) ){
    arg = skip_whitespaces( line );
    if( arg[0] == '#' || arg[0] == ';' ){
      free(line);
      continue;
    }
    if( !strncmp( arg, "<profile>", strlen( "<profile>" ) ) ){
      in_profile = 1;
      p = profile_config_new( );
      free(line);
      if( p == NULL ){
        LOGERROR( "Could not allocate memory for new profile" );
        rc = 1;
        break;
      }
      list_append( c->profiles, p );
      continue;
    }
    if( !strncmp( arg, "</profile>", strlen( "</profile>" ) ) ){
      in_profile = 0;
      STRDUP_IFNOTSET(p->search_filter, OSEARCH_FILTER);
      p = NULL;
      free(line);
      continue;
    }
    arg = strtok( arg, "=" );
    if(arg && *arg != '\n'){
      val = strtok( NULL, "\n");
      /* global conf -> ldap */
      if( !strcmp( arg, "uri" ) ){
        STRDUP_IFNOTSET(c->ldap->uri, val );
      } else if ( !strcmp( arg, "binddn" ) ) {
        STRDUP_IFNOTSET(c->ldap->binddn, val );
      }else if ( !strcmp( arg, "bindpw" ) ) {
        STRDUP_IFNOTSET(c->ldap->bindpw, val );
      }else if ( !strcmp( arg, "version" ) ){
        if(!c->ldap->version) c->ldap->version = atoi(val);
      }else if ( !strcmp( arg, "ssl" ) ){
        STRDUP_IFNOTSET(c->ldap->ssl, val );
      }else if ( !strcmp( arg, "tls_cacertfile" ) ){
        STRDUP_IFNOTSET(c->ldap->tls_cacertfile, val );
      }else if ( !strcmp( arg, "tls_cacertdir" ) ){
        STRDUP_IFNOTSET(c->ldap->tls_cacertdir, val );
      }else if ( !strcmp( arg, "tls_certfile" ) ){
        STRDUP_IFNOTSET(c->ldap->tls_certfile, val );
      }else if ( !strcmp( arg, "tls_certkey" ) ){
        STRDUP_IFNOTSET(c->ldap->tls_certkey, val );
      }else if ( !strcmp( arg, "tls_ciphersuite" ) ){
        STRDUP_IFNOTSET(c->ldap->tls_ciphersuite, val );
      }else if ( !strcmp( arg, "tls_reqcert" ) ){
        STRDUP_IFNOTSET(c->ldap->tls_reqcert, val );
      }else if( !strcmp( arg, "timeout" ) ){
        if( !c->ldap->timeout ) c->ldap->timeout = atoi(val);
      /* profile conf */
      }else if ( !strcmp( arg, "usersdn" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        STRDUP_IFNOTSET(p->usersdn, val );
      }else if ( !strcmp( arg, "search_filter" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        STRDUP_IFNOTSET(p->search_filter, val );
      }else if ( !strcmp( arg, "search_scope" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        if( !strcasecmp( val, "LDAP_SCOPE_BASE" ) ){
          p->search_scope = LA_SCOPE_BASE;
        }else if( !strcasecmp( val, "LDAP_SCOPE_ONELEVEL" ) ){
          p->search_scope = LA_SCOPE_ONELEVEL;
        }else if( !strcasecmp( val, "LDAP_SCOPE_SUBTREE" ) ){
          p->search_scope = LA_SCOPE_SUBTREE;
        }
      /* Group */
      }else if( !strcmp( arg, "groupdn" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        STRDUP_IFNOTSET(p->groupdn, val );
      }else if( !strcmp( arg, "group_search_filter" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        STRDUP_IFNOTSET(p->group_search_filter, val );
      }else if( !strcmp( arg, "member_attribute" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        STRDUP_IFNOTSET(p->member_attribute, val );
      /* Default GW */
      }else if( !strcmp( arg, "redirect_gateway_prefix" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        STRDUP_IFNOTSET(p->redirect_gateway_prefix, val );
      }else if( !strcmp( arg, "redirect_gateway_flags" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        STRDUP_IFNOTSET(p->redirect_gateway_flags, val );
      /* PF */
      }else if( !strcmp( arg, "enable_pf" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        p->enable_pf = string_to_ternary( val );
      }else if( !strcmp( arg, "default_pf_rules" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        STRDUP_IFNOTSET(p->default_pf_rules, val );
#ifdef ENABLE_LDAPUSERCONF
      }else if( !strcmp( arg, "default_profiledn" ) ){
        CHECK_IF_IN_PROFILE( arg, in_profile );
        STRDUP_IFNOTSET(p->default_profiledn, val );
#endif
      }else{
        LOGWARNING("Unrecognized option *%s=%s*", arg, val);
      }

    }
		free( line );
	}
	close( fd );
	return rc;
}




int
config_parse_file_new( config_t *c){
  int rc = 0;
  profile_config_t *p = NULL;
   /* global conf -> ldap */
  p = profile_config_new( );
  list_append( c->profiles, p );
  for(int i=0;i<ldapconfig->klen;i++)
  {
    char *tname=ldapconfig->keymaps[i].name;
    // char *tvalue[256]=ldapconfig->keymaps[i].value;
    if( !strcasecmp(tname, "HOST" ) ){
      STRDUP_IFNOTSET(c->ldap->uri,ldapconfig->keymaps[i].value[0]);
    } else if ( !strcasecmp(tname, "BIND_DN" ) ) {
      STRDUP_IFNOTSET(c->ldap->binddn, ldapconfig->keymaps[i].value[0] );
    }else if ( !strcasecmp(tname, "BIND_PASS" ) ) {
      STRDUP_IFNOTSET(c->ldap->bindpw, ldapconfig->keymaps[i].value[0] );
    }else if ( !strcasecmp(tname, "VERSION" ) ){
      if(!c->ldap->version) c->ldap->version = atoi(ldapconfig->keymaps[i].value[0]);
    }else if ( !strcasecmp(tname, "SSL" ) ){
      STRDUP_IFNOTSET(c->ldap->ssl, ldapconfig->keymaps[i].value[0] );
    }else if ( !strcasecmp(tname, "TLS_CACERTFILE" ) ){
      STRDUP_IFNOTSET(c->ldap->tls_cacertfile, ldapconfig->keymaps[i].value[0] );
    }else if ( !strcasecmp(tname, "TLS_CACERTDIR" ) ){
      STRDUP_IFNOTSET(c->ldap->tls_cacertdir, ldapconfig->keymaps[i].value[0] );
    }else if ( !strcasecmp(tname, "TLS_CERTFILE" ) ){
      STRDUP_IFNOTSET(c->ldap->tls_certfile, ldapconfig->keymaps[i].value[0] );
    }else if ( !strcasecmp(tname, "TLS_CERTKEY" ) ){
      STRDUP_IFNOTSET(c->ldap->tls_certkey, ldapconfig->keymaps[i].value[0] );
    }else if ( !strcasecmp(tname, "TLS_CIPHERSUITE" ) ){
      STRDUP_IFNOTSET(c->ldap->tls_ciphersuite, ldapconfig->keymaps[i].value[0] );
    }else if ( !strcasecmp(tname, "TLS_REQCERT" ) ){
      STRDUP_IFNOTSET(c->ldap->tls_reqcert, ldapconfig->keymaps[i].value[0] );
    }else if( !strcasecmp(tname, "TIMEOUT" ) ){
      if( !c->ldap->timeout ) c->ldap->timeout = atoi(ldapconfig->keymaps[i].value[0]);
    /* profile conf */
    }else if ( !strcasecmp(tname, "BASE_DN" ) ){
      // CHECK_IF_IN_PROFILE( tname, in_profile );
      STRDUP_IFNOTSET(p->basedn, ldapconfig->keymaps[i].value[0] );
    }else if ( !strcasecmp(tname, "USERS_DN" ) ){
      // CHECK_IF_IN_PROFILE( tname, in_profile );
      STRDUP_IFNOTSET(p->usersdn, ldapconfig->keymaps[i].value[0] );
    }else if ( !strcasecmp(tname, "USERS_FILTER" ) ){
      // CHECK_IF_IN_PROFILE( arg, in_profile );
      STRDUP_IFNOTSET(p->search_filter, ldapconfig->keymaps[i].value[0] );
    }else if ( !strcasecmp(tname, "USERS_SEARCH_SCOPE" ) ){
      // CHECK_IF_IN_PROFILE( arg, in_profile );
      if( !strcasecmp( ldapconfig->keymaps[i].value[0], "LDAP_SCOPE_BASE" ) ){
        p->search_scope = LA_SCOPE_BASE;
      }else if( !strcasecmp( ldapconfig->keymaps[i].value[0], "LDAP_SCOPE_ONELEVEL" ) ){
        p->search_scope = LA_SCOPE_ONELEVEL;
      }else if( !strcasecmp( ldapconfig->keymaps[i].value[0], "LDAP_SCOPE_SUBTREE" ) ){
        p->search_scope = LA_SCOPE_SUBTREE;
      }
    /* Group */
    }else if( !strcasecmp( tname, "GROUP_DN" ) ){
      // CHECK_IF_IN_PROFILE( arg, in_profile );
      STRDUP_IFNOTSET(p->groupdn, ldapconfig->keymaps[i].value[0] );
    }else if( !strcasecmp( tname, "GROUP_FILTER" ) ){
      // CHECK_IF_IN_PROFILE( arg, in_profile );
      STRDUP_IFNOTSET(p->group_search_filter, ldapconfig->keymaps[i].value[0] );
    }else if( !strcasecmp(tname, "GROUP_MEMBER_ATTR" ) ){
      // CHECK_IF_IN_PROFILE( arg, in_profile );
      STRDUP_IFNOTSET(p->member_attribute, ldapconfig->keymaps[i].value[0] );
    }else if( !strcasecmp(tname, "GROUP_MAP_FIELD" ) ){
      // CHECK_IF_IN_PROFILE( arg, in_profile );
      if(ldapconfig->keymaps[i].vlen==0)
      {
        p->group_map_field[0]=strdup("cn");
        p->group_map_field[1]=strdup("description");
      }else{
        for(int n=0;n<ldapconfig->keymaps[i].vlen;n++){
          p->group_map_field[n]=strdup(ldapconfig->keymaps[i].value[n]);
        }
      }
    }else{
      LOGWARNING("Unrecognized option *%s=%s*", tname, ldapconfig->keymaps[i].value[0]);
    }
  }
     
	return rc;
}

const char *
config_search_scope_to_string( ldap_search_scope_t scope){

  switch( scope ){
    case LA_SCOPE_BASE:
      return "BASE";
    case LA_SCOPE_ONELEVEL:
      return "ONELEVEL";
    case LA_SCOPE_SUBTREE:
      return "SUBTREE";
  }
  return NULL;
}
void
config_dump( config_t *c){
  LOGDEBUG( "Config Dump: *LDAP:*");
  LOGDEBUG_IFSET(c->ldap->uri,"  URI");
  LOGDEBUG_IFSET(c->ldap->binddn,"  BindDN");
  LOGDEBUG( "  SSL: %s", c->ldap->ssl );
  LOGDEBUG( "  LDAP VERSION: %d", c->ldap->version );
  LOGDEBUG( "  LDAP TIMEOUT: %d", c->ldap->timeout );
  /* Dump each profiles */
  list_item_t *item;
  profile_config_t *p;
  for( item = list_first( c->profiles ); item; item = item->next){
    p = item->data;
    LOGDEBUG( "*Custom Profile:*" );
    LOGDEBUG_IFSET(p->basedn, "  BaseDN");
    LOGDEBUG_IFSET(p->usersdn, "  UsersDN");
    LOGDEBUG( "  Search Scope: %s", config_search_scope_to_string( p->search_scope ) );
    LOGDEBUG( "  Search filter: %s", p->search_filter );
    LOGDEBUG_IFSET(p->groupdn,"  GroupDN");
    LOGDEBUG_IFSET(p->group_search_filter, "  Group Search Filter");
    LOGDEBUG_IFSET(p->member_attribute,"  Member Attribute");
    if(p->group_map_field[0])
    {
      char *f;
      f=char_array_join(p->group_map_field,",");
      LOGDEBUG("  Group Map Fields: %s",f);
      check_and_free(f);
    }
    LOGDEBUG( "  Enable PF: %s", ternary_to_string(p->enable_pf));
    LOGDEBUG( "  Default PF rules: %s", p->default_pf_rules ? p->default_pf_rules : "Undefined" );
#ifdef ENABLE_LDAPUSERCONF
    LOGDEBUG( "  Default Profile DN: %s", p->default_profiledn ? p->default_profiledn : "Undefined" );
#endif

  }
}

int
config_is_pf_enabled( config_t *c ){
  int enabled = 0;
  list_item_t *item;

  for( item = list_first( c->profiles ); item; item = item->next ){
    profile_config_t *pc = item->data;
    if( pc->enable_pf == TERN_TRUE ){
      enabled = 1;
      break;
    }
  }
  return enabled;
}
int
config_is_pf_enabled_for_profile( profile_config_t *p ){
  return p->enable_pf == TERN_TRUE;
}

int
config_is_redirect_gw_enabled( config_t *c ){
  int enabled = 0;
  list_item_t *item;
  profile_config_t *pc = NULL;

  for( item = list_first( c->profiles ); item; item = item->next ){
    pc = item->data;
    if( pc->redirect_gateway_prefix != NULL ){
      enabled = 1;
      break;
    }
  }
  return enabled;
}

int
config_is_redirect_gw_enabled_for_profile( profile_config_t *p ){
  return p->redirect_gateway_prefix != NULL;
}




// 
void config_iptables_printf(ldap_config_keyvalue_t *rules)
{
  int i=0;
  while (i <rules->klen)
  {
    int m=0;
    LOGNOTICE("%d,%s:",i,rules->keymaps[i].name);
    while(m<rules->keymaps[i].vlen){
      LOGNOTICE("\t%d-%d-%s",m,rules->keymaps[i].vlen,rules->keymaps[i].value[m]);
      m++;
    }
    i++;
  }
}
// 
void config_ldap_printf(ldap_config_keyvalue_t *rules)
{
  for(int i=0;i<rules->klen;i++)
  {
    // char *buf;
    if(rules->keymaps[i].name!=NULL){
      if(!strcasecmp(rules->keymaps[i].name,"BIND_PASS"))
      {
        LOGNOTICE("%d-%s=%s",i,rules->keymaps[i].name,"********");
        continue;
      }
      if(rules->keymaps[i].vlen>1){
        char *t;
        t=char_array_join(rules->keymaps[i].value,",");
        LOGNOTICE("%d,%s: %s",i,rules->keymaps[i].name,t);
        check_and_free(t);
      }else{
        LOGNOTICE("%d-%s=%s",i,rules->keymaps[i].name,rules->keymaps[i].value[0]);
      }
    }
  }
}
void config_ldap_plugin_serverinfo_free(ldap_openvpn_server_info *info)
{
  check_and_free((char *)info->dev);
  check_and_free((char *)info->listenip);
  check_and_free((char *)info->netmask);
  check_and_free((char *)info->netaddr);
  check_and_free((char *)info->proto);
  check_and_free((char *)info->serverip);
  check_and_free((char *)info->serverport);
  check_and_free(info);
}

void config_ldap_plugin_free(ldap_config_keyvalue_t *rules)
{
  int i=0;
  while (i <rules->klen)
  {
    int m=0;
    check_and_free(rules->keymaps[i].name);
    while(m<rules->keymaps[i].vlen){
      check_and_free(rules->keymaps[i].value[m]);
      m++;
    }
    i++;
  }
  check_and_free(rules);
  LOGNOTICE("free ldap plugin malloc.");
}

static void config_default_iptable_rules(iptable_rules_action_type ctype)
{
  char allowVpn[128];
  sprintf(allowVpn,"-p %s -m %s --dport %s -j ACCEPT",openvpnserverinfo->proto,openvpnserverinfo->proto,openvpnserverinfo->serverport);
  ldap_plugin_run_system(ctype,"INPUT",allowVpn);
  // 添加FORWORD链默认规则 默认允许DNS解析，最后规则是拒绝所有连接。
  // char * netaddr=GetNetworkAndCIDRAddress(localip,localnetmask);
  ldap_plugin_run_system(ctype,"FORWARD","-p all -j DROP");
  sprintf(allowVpn,"-p tcp -m tcp --dport 53 -s %s -j ACCEPT",openvpnserverinfo->netaddr);
  ldap_plugin_run_system(ctype,"FORWARD",allowVpn);
  sprintf(allowVpn,"-p udp -m udp --dport 53 -s %s -j ACCEPT",openvpnserverinfo->netaddr);
  ldap_plugin_run_system(ctype,"FORWARD",allowVpn);
}
void config_uninit_iptable_rules(ldap_config_keyvalue_t *rules)
{
  int i=0;
  config_default_iptable_rules(IPTABLE_DELETE_ROLE);
  while (i <rules->klen)
  {
    if(rules->keymaps[i].name!=NULL)
    {
      ldap_plugin_run_system(IPTABLE_EMPTY_FILTER,rules->keymaps[i].name,"");
      ldap_plugin_run_system(IPTABLE_DELETE_FILTER,rules->keymaps[i].name,"");
    }
    i++;
  } 
}

void config_init_iptable_rules(ldap_config_keyvalue_t *rules)
{
  int i=0;
  LOGINFO("Starting Initial iptables policy entry。");
  config_default_iptable_rules(IPTABLE_INSERT_ROLE);
  while (i <rules->klen)
  {
    int m=0;
    if(rules->keymaps[i].name!=NULL)
    {
      int ret;
      ret =ldap_plugin_run_system(IPTABLE_CREATE_FILTER,rules->keymaps[i].name,"");
      if(ret!=0)
      {
        i++;
        continue;
      }
      while(m<rules->keymaps[i].vlen){
        if(rules->keymaps[i].value[m]!=NULL)
        {
          ldap_plugin_run_system(IPTABLE_APPEND_ROLE,rules->keymaps[i].name,rules->keymaps[i].value[m]);
        }
        m++;
      }
      // 添加一条返回调用链规则
      ldap_plugin_run_system(IPTABLE_APPEND_ROLE,rules->keymaps[i].name,"-p all -j RETURN");
      i++;
    }
  } 
}

int config_init_ldap_config_set(const char *filename,const char *envp[])
{
  FILE *fh = fopen(filename, "r");
  if( fh == NULL ){
    LOGERROR( "Could not open file %s: (%d) %s", filename, errno, strerror( errno ) );
		return 1;
	}
  yaml_parser_t parser;
  yaml_token_t  token;  
  if(!yaml_parser_initialize(&parser))
  {
    LOGERROR("Failed to initialize parser!");
    return 1;
  }

  /* Set input file */
  yaml_parser_set_input_file(&parser, fh);

  /* BEGIN new code */
  bool haskey = false,hasvalue = false,
       hassequ = false;
  u_int keylayer=0,seqindex=0,keyindex=0;
  
  iptblrules = malloc(sizeof(ldap_config_keyvalue_t));
  ldapconfig = malloc(sizeof(ldap_config_keyvalue_t));
  openvpnserverinfo= malloc(sizeof(ldap_openvpn_server_info));
  memset(iptblrules,0,sizeof(ldap_config_keyvalue_t));
  memset(ldapconfig,0,sizeof(ldap_config_keyvalue_t));
  memset(openvpnserverinfo,0,sizeof(ldap_openvpn_server_info));

  // 保存openvpn基本配置信息。
  const char *verb=get_env("verb",envp);
  openvpnserverinfo->verb=atoi(verb);
  openvpnserverinfo->listenip=strdup(get_env("local_1",envp));
  openvpnserverinfo->serverip=strdup(get_env("ifconfig_local",envp));
  openvpnserverinfo->serverport=strdup(get_env("local_port_1",envp));
  openvpnserverinfo->proto=strdup(!strcasecmp(get_env("proto_1",envp),"udp")?"udp":"tcp");
  openvpnserverinfo->dev=strdup(get_env("dev",envp));
  openvpnserverinfo->netmask=strdup(get_env("ifconfig_netmask",envp));
  openvpnserverinfo->netaddr=GetNetworkAndCIDRAddress(openvpnserverinfo->serverip,get_env("ifconfig_netmask",envp));

  // 
  ldap_config_keyvalue_t *tmpconfig;
  tmpconfig=ldapconfig;
  do {
    char *val;
    yaml_parser_scan(&parser, &token);
    switch(token.type)
    {
    case YAML_BLOCK_MAPPING_START_TOKEN:
      keylayer++;
      break;
    case YAML_KEY_TOKEN: hasvalue=false;haskey=true;break;
    case YAML_VALUE_TOKEN:hasvalue=true;haskey=false;break;
    case YAML_BLOCK_SEQUENCE_START_TOKEN: 
      keylayer++;seqindex=0;hasvalue=true;haskey=false;hassequ = true;break;
    case YAML_BLOCK_END_TOKEN:
      keylayer--; 
      hassequ = false;
      haskey=false;
      seqindex=0;
      hasvalue=false;
      break;
    case YAML_SCALAR_TOKEN: 
      val=(char *)token.data.scalar.value;
      if( keylayer==1 && strcasecmp(val,"ldap")==0){
        keyindex=0;
        tmpconfig=ldapconfig;
        break;
      }
      if( keylayer==1 && strcasecmp(val,"iptablerules")==0){
        keyindex=0;
        tmpconfig=iptblrules;
        break;
      }
      // ldap config 
      if(haskey){
        if(keyindex>=IP_RULE_KEYS_BUF){
          LOGERROR("Error: IP rule keyname exceeding maximum limit %d [%s]。\n",
                IP_RULE_KEYS_BUF,
                val);
          break;
        }
        tmpconfig->keymaps[keyindex].name=strdup(val);
        tmpconfig->klen=++keyindex;
      }else if(hasvalue){
        if(seqindex<IP_RULE_ITEM_BUF && keyindex<=IP_RULE_KEYS_BUF){

          tmpconfig->keymaps[keyindex-1].value[seqindex]=strdup(val);
          if(hassequ)
          {
            tmpconfig->keymaps[keyindex-1].vlen=++seqindex;
          }else{
            tmpconfig->keymaps[keyindex-1].vlen=1;
          }
        }else{
          LOGERROR("Error: IP rule items defined exceed the maximum limit %d [%s]。\n",
                  IP_RULE_ITEM_BUF,
                  val);
        }
      }
      break;
    default:
      break;
    }
    if(token.type != YAML_STREAM_END_TOKEN)
      yaml_token_delete(&token);
  } while(token.type != YAML_STREAM_END_TOKEN);
  yaml_parser_delete(&parser);

  if(DODEBUG(openvpnserverinfo->verb))
  {
    config_ldap_printf(ldapconfig);
    config_iptables_printf(iptblrules);
  }
  fclose(fh);
  return 0;
}