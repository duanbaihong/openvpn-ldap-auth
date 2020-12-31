/**
 * la_ldap.c
 * vim: tabstop=2 softtabstop=2 shiftwidth=2 expandtab
 * Copyright (C) 2010 Emmanuel Bretelle <chantra@debuntu.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <ldap.h>
#include <errno.h>
#include <openvpn-plugin.h>

#include "debug.h"
#include "la_ldap.h"
#include "client_context.h"
#include "config.h"

#ifdef ENABLE_LDAPUSERCONF
#include "ldap_profile.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

#define PF_ALLOW_ALL "[CLIENTS ACCEPT]\n[SUBNETS ACCEPT]\n[END]\n"

int
ldap_tlsreqcert_from_string(char *s){
  if( strcasecmp(s, "never") == 0)
    return LDAP_OPT_X_TLS_NEVER;
  if( strcasecmp(s, "hard") == 0)
    return LDAP_OPT_X_TLS_HARD;
  if (strcasecmp(s, "demand") == 0)
    return LDAP_OPT_X_TLS_DEMAND;
  if (strcasecmp(s, "allow") == 0)
    return LDAP_OPT_X_TLS_ALLOW;
  if (strcasecmp(s, "try") == 0)
    return LDAP_OPT_X_TLS_TRY;

  return -1;
}

void
ldap_context_free( ldap_context_t *l ){
  if( !l ) return;
  if( l->config ) config_free( l->config );
  if( l->action_list) list_free( l->action_list, action_free );
  free( l );
}

ldap_context_t *
ldap_context_new( void ){
  ldap_context_t *l;
  l = malloc( sizeof( ldap_context_t ) );
  if( !l ) return NULL;
  memset( l, 0, sizeof( ldap_context_t ) );
  l->config = config_new( );
  if( !l->config ){
    ldap_context_free( l );
    return NULL;
  }
  l->action_list = list_new( );
  if( !l->action_list ){
    ldap_context_free( l );
    return NULL;
  }
  return l;
}


void
auth_context_free( auth_context_t *a ){
  if( !a ) return;
  if( a->username ) free( a->username );
  if( a->password ) free( a->password );
  if( a->auth_control_file ) free( a->auth_control_file );
  FREE_IF_NOT_NULL( a->pf_file );
  free( a );
  return;
}


auth_context_t *
auth_context_new( void ){
  auth_context_t *a = NULL;
  a = la_malloc( sizeof( auth_context_t ) );
  if( a ) la_memset( a, 0, sizeof( auth_context_t ) );
  return a;
}

/**
 * la_ldap_set_timeout:
 * Set a timeout according to config
 */
void
la_ldap_set_timeout( config_t *conf, struct timeval *timeout){
  timeout->tv_sec = conf->ldap->timeout;
  timeout->tv_usec = 0;
}

/**
 * la_ldap_errno
 * return the last set error
 */
int
la_ldap_errno( LDAP *ldap ){
  int rc;
  ldap_get_option(ldap, LDAP_OPT_ERROR_NUMBER, &rc);
  return rc;
}

/**
 * Translate config scope values to ldap scope values
 */
static int
la_ldap_config_search_scope_to_ldap( ldap_search_scope_t scope ){
  int ldap_scope = 0;
  if( scope == LA_SCOPE_BASE )
    ldap_scope = LDAP_SCOPE_BASE;
  else if( scope == LA_SCOPE_ONELEVEL )
    ldap_scope = LDAP_SCOPE_ONELEVEL;
  else if( scope == LA_SCOPE_SUBTREE )
    ldap_scope = LDAP_SCOPE_SUBTREE;

  return ldap_scope;
}

static const char *
la_ldap_ldap_scope_to_string( int scope ){
  switch( scope ){
    case LDAP_SCOPE_BASE:
      return "BASE";
    case LDAP_SCOPE_ONELEVEL:
      return "ONELEVEL";
    case LDAP_SCOPE_SUBTREE:
      return "SUBTREE";
  }
  return NULL;
}

/**
 * PF handling
 */

/**
 * return a static string interpreting
 * LDAP pf_[client|subnet]_default_accept
 * suitable for pf_file insertion
 */
char *
la_ldap_default_rule_to_string( ternary_t rule ){
  if( rule == TERN_TRUE )
    return "ACCEPT";
  if( rule == TERN_FALSE )
    return "DROP";
  return "";
}

#ifdef ENABLE_LDAPUSERCONF
char *
la_ldap_generate_pf_rules( ldap_profile_t *lp ){
  char *res = NULL;
  res = strdupf("[CLIENTS %s]\n\
%s\n\
[SUBNETS %s]\n\
%s\n\
[END]\n",
      la_ldap_default_rule_to_string( lp->pf_client_default_accept ),
      lp->pf_client_rules ? lp->pf_client_rules : "",
      la_ldap_default_rule_to_string( lp->pf_subnet_default_accept ),
      lp->pf_subnet_rules ? lp->pf_subnet_rules : "" );
  LOGDEBUG("pf_rules = %s", res);
  return res;
}
#endif

int
la_ldap_write_to_pf_file( char *pf_file, char *value )
{
  int fd, rc = 0;
  if( pf_file == NULL ){
    LOGERROR( "pf_file is null");
    return 1;
  }

  fd = open( pf_file, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU );
  if( fd == -1 ){
    LOGERROR( "Could not open file %s: (%d) %s", pf_file, errno, strerror( errno ) );
    return 1;
  }
  rc = write( fd, value, strlen(value) );
  if( rc == -1 ){
    LOGERROR( "Could not write value %s to  file %s: (%d) %s", value, pf_file, errno, strerror( errno ) );
    rc = 1;
  }else if( rc !=strlen(value) ){
    LOGERROR( "Could not write all of  %s to file %s", value, pf_file );
    rc = 1;
  }else{
    rc = 0;
  }
  if( close( fd ) != 0 ){
    LOGERROR( "Could not close file %s: (%d) %s", pf_file, errno, strerror( errno ) );
  }
  return rc;
}


/**
 * la_ldap_handle_pf_file
 * Given the plugin config and the client_context
 * will write to pf_file the right
 */
int
la_ldap_handle_pf_file(config_t *c, client_context_t *cc, char *pf_file){
  profile_config_t *p = cc->profile;
  int rc = 0;

  /* check if pf is enabled */
  LOGDEBUG("PF enable for this profile: %s",
        p->enable_pf == TERN_TRUE ? "TRUE" : "FALSE" );
  /* write to pf_file */
  if( pf_file == NULL && config_is_pf_enabled(c) ){
    LOGERROR("PF is enabled but environment pf_file variable is NULL.");
    return 1;
  }else if( pf_file ){
    if( p->enable_pf == TERN_TRUE ){
#ifdef ENABLE_LDAPUSERCONF
      ldap_profile_t *lp = cc->ldap_account->profile;
      /* We only write PF rules from LDAP if
       * pf_client_default_accept and pf_subnet_default_accept
       * are defined
       */
      if( lp->pf_client_default_accept != TERN_UNDEF && lp->pf_subnet_default_accept != TERN_UNDEF ){
        char *pf_rules = NULL;
        pf_rules = la_ldap_generate_pf_rules( lp );
        if( pf_rules ){
          LOGDEBUG("Using PF rules from ldap backend");
          rc = la_ldap_write_to_pf_file( pf_file, pf_rules );
          la_free( pf_rules );
        }else{
          LOGERROR("ldap_profile_handle_pf_file: could not generate pf_rules");
          return 1;
        }
      }else
#endif
      if( p->default_pf_rules ){
        LOGDEBUG("Using default PF rules from config");
        char *rules = str_replace_all( p->default_pf_rules, "\\n", "\n" );
        int res = la_ldap_write_to_pf_file( pf_file, rules );
        if( rules ) la_free( rules );
        return res;
      }else{
        /* set up default pf_rules */
        /*
         * If pf_client_default_accept or pf_subnet_default_accept
         * is not defined, we default to openvpn standard behaviour:
         * allow everything
         */
        LOGDEBUG("No PF rules found, default to accept all");
        return la_ldap_write_to_pf_file( pf_file, PF_ALLOW_ALL);
      }
    }else{
        /* profile has PF disabled */
        LOGDEBUG("PF rules disabled for this profile, default to accept all");
        return la_ldap_write_to_pf_file( pf_file, PF_ALLOW_ALL );
    }
  }
  return rc;
}


/**
 * Search for a user's DN given a config profile
 * On success, return userdn (much be freed by caller)
 * On error, return NULL
 */


char *
ldap_find_user_for_profile( LDAP *ldap, ldap_context_t *ldap_context, const char *username, profile_config_t *p){
  char *userdn = NULL;
  char *real_username = NULL;
  struct timeval timeout;
  char *attrs[] = { NULL };
  char          *dn = NULL;
  LDAPMessage *e, *result = NULL;
  config_t *config = NULL;
  int rc;
  char *search_filter = NULL;
  int ldap_scope = 0;


  config = ldap_context->config;

  /* initialise timeout values */
  la_ldap_set_timeout( config, &timeout );

  if( p->redirect_gateway_prefix
      && strncmp(  p->redirect_gateway_prefix, username, strlen( p->redirect_gateway_prefix ) ) == 0 ){
    real_username = strdup( username + strlen( p->redirect_gateway_prefix ) );
  }else{
    real_username = strdup( username );
  }
  if( real_username && p->search_filter ){
    search_filter = str_replace(p->search_filter, "%u", real_username );
  }
  if( real_username ) la_free( real_username );

  if( DODEBUG( ldap_context->verb ) )
    LOGDEBUG( "Searching user using filter %s with usersdn: %s and scope %s", search_filter, p->usersdn, la_ldap_ldap_scope_to_string( p->search_scope ) );
  ldap_scope = la_ldap_config_search_scope_to_ldap( p->search_scope );
  rc = ldap_search_ext_s( ldap, p->usersdn, ldap_scope, search_filter, attrs, 0, NULL, NULL, &timeout, 1000, &result );
  if( rc == LDAP_SUCCESS ){
    /* Check how many entries were found. Only one should be returned */
    int nbrow = ldap_count_entries( ldap, result );
    if( nbrow > 1 ){
      LOGERROR( "ldap_search_ext_s returned %d results, only 1 is supported", ldap_count_entries( ldap, result ) );
    }else if( nbrow == 0 ){
      if( DODEBUG( ldap_context->verb ) )
        LOGDEBUG( "ldap_search_ext_s: unknown user %s in usersdn %s and scope %s", username, p->usersdn, la_ldap_ldap_scope_to_string( p->search_scope ) );
    }else if( nbrow == 1 ){
      /* get the first entry (and only) */
      e =  ldap_first_entry( ldap, result );
      if( e != NULL ){
        dn = ldap_get_dn( ldap, e );
        if( DODEBUG( ldap_context->verb ) )
          LOGDEBUG("Found dn: %s", dn );
      }else{
        LOGERROR( "searched returned and entry but we could not retrieve it!!!" );
      }
    }
  }else{
    LOGERROR( "ldap_search_ext_s did not succeed (%d) %s", rc, ldap_err2string( rc ));
  }
  /* free the returned result */
  if( result != NULL ) ldap_msgfree( result );

  if( dn ){
    userdn = strdup( dn );
    /* finally, if a DN was returned, free it */
    ldap_memfree( dn );
  }
  if( search_filter ) free( search_filter );
  return userdn;

}

/**
 * Search for a user's DN
 * Given a search_filter and context, will search for a user
 * Each profiles will be tried one after another one until a
 * match is found or no more profile are available
 * On success
 *  * return userdn (much be freed by caller)
 *  * set set userdn and used profile in client_context
 * On error, return NULL
 */
char *
ldap_find_user( LDAP *ldap, ldap_context_t *ldap_context, const char *username, client_context_t *cc ){
  config_t *config = NULL;
  char *userdn = NULL;
  profile_config_t *p = NULL;
  list_item_t *item = NULL;

  cc->profile = NULL;

  /* arguments sanity check */
  if( !ldap_context || !username || !ldap){
    LOGERROR("ldap_find_user missing required parameter");
    return NULL;
  }

  config = ldap_context->config;

  if( list_length( config->profiles ) != 0 ){
    for( item = list_first( config->profiles ); item; item = item->next ){
      p = item->data;
      userdn = ldap_find_user_for_profile( ldap, ldap_context, username, p );
      if( userdn ){
        if( cc->user_dn ) la_free( cc->user_dn );
        cc->user_dn = strdup( userdn );
        cc->profile = p;
        break;
      }
    }
  }else{
    LOGERROR("No profiles defined. Please make sure you have a <profile></profile> section in your config.");
  }

  return userdn;
}


/**
 * Set up a connection to LDAP given the context configuration
 * Do not bind to LDAP, use ldap_bindn for that purpose
 */
LDAP *
connect_ldap( ldap_context_t *l ){
  LDAP *ldap;
  int rc;
  config_t *config = l->config;
  int ldap_tls_require_cert;
  struct timeval timeout;

  /* SSL/TLS */
  if( strcmp( config->ldap->ssl, "start_tls" ) == 0){
    /**
     * TODO handle certif properly. Seems that LDAP_OPT_X_TLS_REQUIRE_CERT
     * needs to be set up before handle initialization
     */
    ldap_tls_require_cert = ldap_tlsreqcert_from_string(config->ldap->tls_reqcert);
    if( ldap_tls_require_cert == -1){
      LOGERROR( "%s is not a valid TLS_REQCERT value", config->ldap->tls_reqcert);
      return NULL;
    }
    rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &ldap_tls_require_cert );
    if( rc != LDAP_OPT_SUCCESS ){
      LOGERROR( "ldap_set_option TLS_REQ_CERT returned (%d) \"%s\"", rc, ldap_err2string(rc) );
      return NULL;
    }
  }

  /* init connection to ldap */
  rc = ldap_initialize(&ldap, config->ldap->uri);
  if( rc!= LDAP_SUCCESS ){
    LOGERROR( "ldap_initialize returned (%d) \"%s\" : %s", rc, ldap_err2string(rc), strerror(errno) );
    goto connect_ldap_error;
  }
  /* Version */
  rc = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &(config->ldap->version));
  if( rc != LDAP_OPT_SUCCESS ){
    LOGERROR( "ldap_set_option version %d returned (%d) \"%s\"", config->ldap->version, rc, ldap_err2string(rc) );
    goto connect_ldap_error;
  }
  /* Timeout */
  la_ldap_set_timeout( config, &timeout);
  rc = ldap_set_option(ldap, LDAP_OPT_NETWORK_TIMEOUT, &timeout );
  if( rc != LDAP_OPT_SUCCESS ){
    LOGERROR( "ldap_set_option timeout %ds returned (%d) \"%s\"", config->ldap->timeout, rc, ldap_err2string(rc) );
    goto connect_ldap_error;
  }
  /* SSL/TLS */
  if( strcmp( config->ldap->ssl, "start_tls" ) == 0){
    /*TODO handle certif properly */
    rc = ldap_start_tls_s( ldap, NULL, NULL );
    if( rc != LDAP_SUCCESS && rc !=  LDAP_LOCAL_ERROR ){
      LOGERROR( "ldap_start_tls_s returned (%d) \"%s\"", rc, ldap_err2string(rc) );
      goto connect_ldap_error;
    }else if( rc == LDAP_LOCAL_ERROR ){
      LOGWARNING( "ldap_start_tls_s TLS context already exist" );
    }
  }
  return ldap;

connect_ldap_error:
  rc = ldap_unbind_ext_s( ldap, NULL, NULL );
  if( rc != LDAP_SUCCESS ){
    LOGERROR( "ldap_unbind_ext_s returned: %d/0x%2X %s", rc, rc, ldap_err2string( rc ) );
  }
  return NULL;
}

/**
 * bind given ldap connection with username and password
 * Anonymous binding is achived by providing NULL username and password
 */

int
ldap_binddn( LDAP *ldap, const char *username, const char *password ){
  int rc;
  struct berval bv, *servcred = NULL;

  if( password && strlen(password) ){
    bv.bv_len = strlen(password);
    bv.bv_val = (char *)password;
  }else{
    bv.bv_len = 0;
    bv.bv_val = NULL;
  }
  rc = ldap_sasl_bind_s( ldap, username, LDAP_SASL_SIMPLE, &bv, NULL, NULL, &servcred);
  if( servcred ) ber_bvfree( servcred );
  return rc;
}

/**
 * Check if userdn belongs to group
 */
int
ldap_group_membership( LDAP *ldap, ldap_context_t *ldap_context, client_context_t *cc ){
  struct timeval timeout;
  LDAPMessage *result = NULL;
  config_t *config = NULL;
  char *search_filter = NULL;
  int rc;
  int res = 1;
  char filter[]="(&(%s=%s)%s)";
  int ldap_scope = 0;
  char *userdn = cc->user_dn;
  profile_config_t *p = cc->profile;

  char *attrs[ldap_array_len(p->group_map_field)+1];
  int i=0;
  while(p->group_map_field[i]!=NULL)
  {
    attrs[i]=p->group_map_field[i];
    i++;
  }
  attrs[i]=NULL;
  /* arguments sanity check */
  if( !ldap_context || !userdn || !ldap){
    LOGERROR("ldap_group_membership missing required parameter");
    return 1;
  }
  config = ldap_context->config;

  /* initialise timeout values */
  la_ldap_set_timeout( config, &timeout);
  if( userdn && p->group_search_filter && p->member_attribute ){
    search_filter = strdupf(filter,p->member_attribute, userdn, p->group_search_filter);
  }

  ldap_scope = la_ldap_config_search_scope_to_ldap( p->search_scope );
  // ldap_scope = la_ldap_config_search_scope_to_ldap( p->search_scope );
  if( DODEBUG( ldap_context->verb ) )
    LOGDEBUG( "Searching user groups using filter %s with usersdn: %s and scope %s", search_filter, p->groupdn, la_ldap_ldap_scope_to_string( p->search_scope ) );

  rc = ldap_search_ext_s( ldap, p->groupdn, ldap_scope, search_filter, attrs, 0, NULL, NULL, &timeout, 1000, &result );
  if( rc == LDAP_SUCCESS ){
    /* Check how many entries were found. Only one should be returned */
    int nbrow = ldap_count_entries( ldap, result );
    if( nbrow < 1 ){
      LOGWARNING( "ldap_search_ext_s: user %s do not match group filter %s", userdn, search_filter );
    }else{
      if( DODEBUG( ldap_context->verb ) )
        LOGDEBUG( "User %s matches %d groups with filter %s", userdn, nbrow, search_filter );
      res = 0;
    }
    LDAPMessage *entry;
    struct berval **vals;
    char *attr;
    int group_num=0;
    for (entry = ldap_first_entry(ldap, result); entry != NULL; entry = ldap_next_entry(ldap, entry))
    {
      BerElement *ber=NULL;
      for(attr=ldap_first_attribute(ldap,entry,&ber);attr!=NULL;attr=ldap_next_attribute(ldap,entry,ber))
      {
        for(idx=0;cc->profile->group_map_field[idx]!=NULL;idx++){
          if(!strcasecmp(attr,cc->profile->group_map_field[idx]))
          {
            vals=ldap_get_values_len(ldap,entry,attr);
            if(vals!=NULL)
            {
              if(!strcasecmp(attr,"cn"))
              {
                cc->groups[group_num]->group_name=strdup(vals[0]->bv_val);
              }
              if(!strcasecmp(attr,"description"))
              {
                cc->groups[group_num]->group_description = strdup(vals[0]->bv_val);
              }
              LOGDEBUG("Get profile %s value length %d, char length: %s",attr,ldap_array_len(vals),vals[0]->bv_val);
            }
            ldap_value_free_len(vals);
          }
        }
        ldap_memfree( attr );
      }
      group_num++;
      if(ber != NULL) ber_free(ber, 0);
    }
    ldap_msgfree(entry);
  }
  /* free the returned result */
  if ( result != NULL ) ldap_msgfree( result );
  if( search_filter ) free( search_filter );
  return res;
}

int
la_ldap_handle_authentication( ldap_context_t *l, action_t *a){
  LDAP *ldap = NULL;
  config_t *config = l->config;
  auth_context_t *auth_context = a->context;
  client_context_t *client_context = a->client_context;
  char *userdn = NULL;
  int rc;
  int res = OPENVPN_PLUGIN_FUNC_ERROR;

  /* Connection to LDAP backend */
  ldap = connect_ldap( l );
  if( ldap == NULL ){
    LOGERROR( "Could not connect to URI %s", config->ldap->uri );
    goto la_ldap_handle_authentication_exit;
  }
  /* bind to LDAP server anonymous or authenticated */
  rc = ldap_binddn( ldap, config->ldap->binddn, config->ldap->bindpw );
  switch( rc ){
    case LDAP_SUCCESS:
      if( DOINFO( l->verb ) )
        LOGINFO( "ldap_sasl_bind_s %s success", config->ldap->binddn ? config->ldap->binddn : "Anonymous" );
      break;
    case LDAP_INVALID_CREDENTIALS:
      LOGERROR( "ldap_binddn: Invalid Credentials" );
      goto la_ldap_handle_authentication_free;
    default:
      LOGERROR( "ldap_binddn: return value: %d/0x%2X %s", rc, rc, ldap_err2string( rc ) );
      goto la_ldap_handle_authentication_free;
  }

  /* find user and return userdn */
  userdn = ldap_find_user( ldap, l, auth_context->username, client_context );
  if( !userdn ){
    LOGWARNING( "LDAP user *%s* was not found", auth_context->username );
    goto la_ldap_handle_authentication_free;
  }

  if (auth_context && l->config ){
      if (auth_context->username && strlen (auth_context->username) > 0 && auth_context->password){
      if (DOINFO (l->verb)) {
          LOGINFO ("LDAP-AUTH: Authenticating Username:%s", auth_context->username );
      }
      rc = ldap_binddn( ldap, userdn, auth_context->password );
      if( rc != LDAP_SUCCESS ){
        LOGERROR( "rebinding: return value: %d/0x%2X %s", rc, rc, ldap_err2string( rc ) );
        res = OPENVPN_PLUGIN_FUNC_ERROR;
        goto la_ldap_handle_authentication_free;
      }else{
        /* success, let set our return value to SUCCESS */
        if( DOINFO( l->verb ) )
          LOGINFO( "User *%s* successfully authenticate", auth_context->username );
#ifdef ENABLE_LDAPUSERCONF
        /* load user settings from LDAP profile */
        ldap_account_load_from_dn( l, ldap, userdn, client_context );
        /* check if user timeframe is allowed start_date, end_date */
        if( ldap_profile_handle_allowed_timeframe( client_context->ldap_account->profile ) != 0 ){
          res = OPENVPN_PLUGIN_FUNC_ERROR;
          goto la_ldap_handle_authentication_free;
        }
        if(DODEBUG(l->verb))
          ldap_account_dump( client_context->ldap_account );
#endif
        /* handle pf_rules if any, default value otherwise */
        la_ldap_handle_pf_file( config, client_context, auth_context->pf_file );

        /* check if user belong to right groups */
        if( client_context->profile->groupdn && client_context->profile->group_search_filter && client_context->profile->member_attribute ){
            rc = ldap_binddn( ldap, config->ldap->binddn, config->ldap->bindpw );
            rc = ldap_group_membership( ldap, l, client_context  );
            if( rc == 0 ){
              res = OPENVPN_PLUGIN_FUNC_SUCCESS;
            }
        }else{
          res = OPENVPN_PLUGIN_FUNC_SUCCESS;
        }
      }
    }
  }
la_ldap_handle_authentication_free:
  rc = ldap_unbind_ext_s( ldap, NULL, NULL );
  if( rc != LDAP_SUCCESS ){
    LOGERROR( "ldap_unbind_ext_s: return value: %d/0x%2X %s", rc, rc, ldap_err2string( rc ) );
  }
  if( userdn ) free( userdn );

la_ldap_handle_authentication_exit:

  return res;

}
