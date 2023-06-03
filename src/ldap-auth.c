/*
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 * ldap-auth.c
 * OpenVPN LDAP authentication plugin
 *
 *  Copyright (C) 2009 Emmanuel Bretelle <chantra@debuntu.org>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 *  USA.
 */


#include "config.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/time.h>
#include <sys/resource.h>
#endif

#include <openvpn-plugin.h>
#include <errno.h>
#include <ldap.h>

#include <pthread.h>

#include "queue.h"
#include "cnf.h"
#include "utils.h"
#include "debug.h"
#include "action.h"
#include "list.h"
#include "la_ldap.h"
#include "la_iptables.h"
#include "client_context.h"
#include "ldap_profile.h"

#define DFT_REDIRECT_GATEWAY_FLAGS "def1 bypass-dhcp"
#define OCONFIG "/etc/openvpn/openvpn-ldap.yaml"
// #define OCONFIG "/etc/openvpn/openvpn-ldap.conf"
pthread_t action_thread = 0;

static void * action_thread_main_loop(void *c);
/*
 * Name/Value pairs for conversation function.
 * Special Values:
 *
 *  "USERNAME" -- substitute client-supplied username
 *  "PASSWORD" -- substitute client-specified password
 */


#if defined(HAVE_GETRLIMIT) && defined(RLIMIT_CORE)
    static void unlimit_core_size(void)
{
  struct rlimit lim;

  if(getrlimit(RLIMIT_CORE, &lim) != 0){
    LOGERROR("Could not get Core file size limits, err (%d): %s", errno, strerror(errno));
    return;
  }
  if (lim.rlim_max == 0)
  {
    LOGERROR("Cannot set core file size limit; disallowed by hard limit");
    return;
  }
  else if (lim.rlim_max == RLIM_INFINITY || lim.rlim_cur < lim.rlim_max)
  {
    lim.rlim_cur = lim.rlim_max;
    if (setrlimit(RLIMIT_CORE, &lim) != 0){
      LOGERROR("Could not set RLIMIT_CORE to %lld", lim.rlim_cur);
    }
  }else {
    LOGDEBUG("Limit not set, soft limit %lld, hardlimit %lld", lim.rlim_cur, lim.rlim_max);
  }
}
#endif

OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v2 (unsigned int *type_mask, const char *argv[], const char *envp[], struct openvpn_plugin_string_list **return_list)
{

  ldap_context_t *context;
  const char *daemon_string = NULL;
  const char *log_redirect = NULL;

  const char *configfile = NULL;
  int rc = 0;
  uint8_t     allow_core_files = 0;

  if(InitConnVpnQueue(&ConnVpnQueue_r))
    LOGINFO("Initial connection queue succeeded");
  /* Are we in daemonized mode? If so, are we redirecting the logs? */
  // dump_env(envp);
  daemon_string = get_env ("daemon", envp);
  use_syslog = 0;
  if( daemon_string && daemon_string[0] == '1'){
    log_redirect = get_env ("daemon_redirect", envp);
    if( !(log_redirect && log_redirect[0] == '1'))
      use_syslog = 1;
  }
  /*
   * Allocate our context
   */
  context = ldap_context_new( );
  if( !context ){
    LOGERROR( "Failed to initialize ldap_context, no memory available?" );
    goto error;
  }
  /*
   * Intercept the --auth-user-pass-verify callback.
   */
  *type_mask = OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY)
               | OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_LEARN_ADDRESS);

   while ( ( rc = getopt ( string_array_len (argv), (char **)argv, ":H:D:c:t:WZC" ) ) != - 1 ){
    switch( rc ) {
      case 'H':
        context->config->ldap->uri = strdup(optarg);
        break;
      case 'Z':
        context->config->ldap->ssl = strdup("start_tls");
        break;
      case 'D':
        context->config->ldap->binddn = strdup(optarg);
        break;
      case 'W':
        context->config->ldap->bindpw = get_passwd("BindPW Password: ");
        //printdebug( "Password is %s: length: %d\n", config->bindpw, strlen(config->bindpw) );
        break;
      case 'c':
        configfile = optarg;
        break;
      case 't':
        context->config->ldap->timeout = atoi( optarg );
        break;
      case 'C':
        LOGDEBUG("Core file generation requested");
        allow_core_files = 1;
        break;
      case '?':
        LOGERROR("Unknown Option -%c !!", optopt );
        break;
      case ':':
        LOGERROR ("Missing argument for option -%c !!", optopt );
        break;
      default:
        LOGERROR ("?? getopt returned character code 0%o ??", rc);
        abort();
    }
  }

#if defined(HAVE_GETRLIMIT) && defined(RLIMIT_CORE)
  if (allow_core_files){
    LOGDEBUG ("Setting core file");
    unlimit_core_size();
  }
#endif

  /**
   * Parse configuration file is -c filename is provided
   * If not provided, use a default config file OCONFIG
   * This file must exists even though it might be empty
   */
  if( configfile == NULL) {
    configfile = OCONFIG;
  }
  const char *verb_string = get_env ("verb", envp);
  if (verb_string)
    context->verb = atoi (verb_string);
  // 解析配置文件信息
  if( config_init_ldap_config_set( configfile, envp ) ){
    goto error;
  }
  // 初始配置文件信息
  config_parse_file( context->config );
  /**
   * Set default config values
   */
  config_set_default( context->config );

  //
  profile_config_t *pro_fd=(profile_config_t *)context->config->profiles->first->data;
  if(pro_fd->enable_ldap_iptable>0) config_load_ldap_groups_profiles(context);
  LdapIptableRoles *tlp=pro_fd->iptable_rules;
  
  config_iptable_role_merge(tlp,iptblrules);
  // 
  if( DODEBUG( context->verb ) )
  {
    config_dump( context->config);
    config_iptables_printf(tlp);
  }
  // 初始iptables规则。
  config_init_iptable_rules(tlp);
  /* when ldap userconf is define, we need to hook onto those callbacks */
  if( config_is_pf_enabled( context->config )){
    *type_mask |= OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_ENABLE_PF);
  }
#ifdef ENABLE_LDAPUSERCONF
  *type_mask |= OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_CLIENT_CONNECT_V2)
                | OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_CLIENT_DISCONNECT);
#else
  if( config_is_redirect_gw_enabled( context->config ) ){
    *type_mask |= OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_CLIENT_CONNECT_V2);
  }
#endif



  /* set up mutex/cond */
  pthread_mutex_init (&action_mutex, NULL);
  pthread_cond_init (&action_cond, NULL);

  /* start our authentication thread */
  pthread_attr_init(&action_thread_attr);
  pthread_attr_setdetachstate(&action_thread_attr, PTHREAD_CREATE_JOINABLE);
  rc = pthread_create(&action_thread, &action_thread_attr, action_thread_main_loop, context);
  
  switch( rc ){
    case EAGAIN:
      LOGERROR( "pthread_create returned EAGAIN: lacking resources" );
      break;
    case EINVAL:
      LOGERROR( "pthread_create returned EINVAL: invalid attributes" );
      break;
    case EPERM:
      LOGERROR( "pthread_create returned EPERM: no permission to create thread" );
      break;
    case 0:
      break;
    default:
      LOGERROR( "pthread_create returned an unhandled value: %d", rc );
  }
  if( rc == 0)
    return (openvpn_plugin_handle_t) context;

  /* Failed to initialize, free resources */
  pthread_attr_destroy( &action_thread_attr );
  pthread_mutex_destroy( &action_mutex );
  pthread_cond_destroy( &action_cond );

error:
  if ( context ){
    ldap_context_free (context);
  }
  return NULL;
}

OPENVPN_EXPORT int
openvpn_plugin_func_v2 (openvpn_plugin_handle_t handle,
                        const int type,
                        const char *argv[],
                        const char *envp[],
                        void *per_client_context,
                        struct openvpn_plugin_string_list **return_list)
{
  ldap_context_t *context = (ldap_context_t *) handle;
  auth_context_t *auth_context = NULL;
  action_t *action = NULL;


  int res = OPENVPN_PLUGIN_FUNC_ERROR;

  if (type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY){
    /* get username/password/auth_control_file from envp string array */
    const char *username = get_env ("username", envp);
    const char *password = get_env ("password", envp);
    const char *auth_control_file = get_env ( "auth_control_file", envp );
    const char *pf_file = get_env ("pf_file", envp);



    /* required parameters check */
    if (!username){
      LOGERROR("No username supplied to OpenVPN plugin");
      return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    auth_context = auth_context_new( );
    if( !auth_context ){
      LOGERROR( "Could not allocate auth_context before calling thread" );
      return res;
    }
    if( username ) auth_context->username = strdup( username );
    if( password ) auth_context->password = strdup( password );
    if( pf_file ) auth_context->pf_file = strdup( pf_file );
    if( auth_control_file ) auth_context->auth_control_file = strdup( auth_control_file );
    /* If some argument were missing or could not be duplicate */
    if( !(auth_context->username && auth_context->password && auth_context->auth_control_file ) ){
      auth_context_free( auth_context );
      return res;
    }
    action = action_new( );
    action->type = LDAP_AUTH_ACTION_AUTH;
    action->context = auth_context;
    action->client_context = per_client_context;
    action->context_free_func = (void *)auth_context_free;
    action_push( context->action_list, action );
    return OPENVPN_PLUGIN_FUNC_DEFERRED;
  }
  else if (type == OPENVPN_PLUGIN_ENABLE_PF){
    /* unfortunately, at this stage we dont know anything about the client
     * yet. Let assume it is enabled, we will define default somewhere
     */
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
  }else if( type == OPENVPN_PLUGIN_CLIENT_CONNECT_V2 ){
    /* on client connect, we return conf options through return list
     */
    const char *username = get_env ("username", envp);
    client_context_t *cc = per_client_context;
    char *ccd_options = NULL;
    /* sanity check */
    if (!username){
      LOGERROR("No username supplied to OpenVPN plugin");
      return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    if (!cc || !cc->profile){
      LOGERROR("No profile found for user");
      return OPENVPN_PLUGIN_FUNC_ERROR;
    }
#ifdef ENABLE_LDAPUSERCONF
    ccd_options = ldap_account_get_options_to_string( cc->ldap_account );
#endif
    if( cc->profile->redirect_gateway_prefix && strlen( cc->profile->redirect_gateway_prefix ) > 0 ){
      /* do the username start with prefix? */
      if( strncmp( cc->profile->redirect_gateway_prefix, username, strlen( cc->profile->redirect_gateway_prefix ) ) == 0 ){
        char *tmp_ccd = ccd_options;
        ccd_options = strdupf("push \"redirect-gateway %s\"\n%s",
                            cc->profile->redirect_gateway_flags ? cc->profile->redirect_gateway_flags : DFT_REDIRECT_GATEWAY_FLAGS,
                            tmp_ccd ? tmp_ccd : "");
        if( tmp_ccd ) la_free( tmp_ccd );
      }
    }
    if( ccd_options ){
      *return_list = la_malloc( sizeof( struct openvpn_plugin_string_list ) );
      if( *return_list != NULL){
        (*return_list)->next = NULL;
        (*return_list)->name = strdup( "config" );
        (*return_list)->value = ccd_options;
      }
    }
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
  }
#ifdef ENABLE_LDAPUSERCONF
  else if( type == OPENVPN_PLUGIN_CLIENT_DISCONNECT ){
    /* nothing done for now
     * potentially, session could be logged
     */
    LOGINFO("exit status code: %d",OPENVPN_PLUGIN_CLIENT_DISCONNECT);
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
  }
#endif
  else if(type == OPENVPN_PLUGIN_LEARN_ADDRESS){
    client_context_t *cc = per_client_context;
    LOGINFO("PLUGIN_LEARN_ADDRESS:%s %s", argv[1],argv[2]);
    if(cc->user_dn){
      LOGINFO("client user_dn:%s",cc->user_dn);
    }
    if(cc->group_len>0){
      LOGINFO("client group lenght:%s",cc->group_len);
      for(int i=0; i<cc->group_len; i++){
        LOGINFO("client group name:%s",cc->groups[i].groupname);
        LOGINFO("client group description:%s",cc->groups[i].description);
      }
    }
    if(string_array_len(argv)>1){
      if(!strcasecmp(argv[1],"add")) 
      {
        if(argv[2]!=NULL && argv[3]!=NULL && cc->group_len>0 )
        {
          VpnData *con_value=malloc(sizeof(VpnData));
          con_value->ip=strdup((char *)argv[2]);
          con_value->username=strdup((char *)argv[3]);
          con_value->group_len=cc->group_len;
          con_value->groups=cc->groups;
          if(JoinVpnQueue(ConnVpnQueue_r,con_value))
          {
            LOGINFO("Join current ip [%s] and username [%s] connection data to the queue successfully, current queue num: %d",
              con_value->ip,
              con_value->username,
              getVpnQueueLength(ConnVpnQueue_r));
            la_learn_roles_add(con_value);
          }else
          {
            LOGERROR("Join current ip [%s] and username [%s] connection data to the queue error!",con_value->ip,con_value->username);
          }
        }
      }
      else if(!strcasecmp(argv[1],"update"))
      {
        VpnData *old_value,*new_value;
        char *ip = (char *)argv[2];
        // 取出原数据
        if(ByValueLeaveVpnQueue(ConnVpnQueue_r,ip,&old_value))
        {
          LOGINFO("test:%s",old_value->group_len);
          la_learn_roles_delete(old_value);
        }
        LOGINFO("%s","test");
        // 更新新数据
        new_value=malloc(sizeof(VpnData));
        new_value->ip=strdup(ip);
        new_value->username=strdup((char *)argv[3]);
        new_value->group_len=cc->group_len;
        new_value->groups=cc->groups;
        if(JoinVpnQueue(ConnVpnQueue_r,new_value))
        {
          LOGINFO("Join current ip [%s] and username [%s] connection data to the queue successfully, current queue num: %d",
              new_value->ip,
              new_value->username,
              getVpnQueueLength(ConnVpnQueue_r));
          la_learn_roles_add(new_value);
        }else
        {
          LOGERROR("Join current ip [%s] and username [%s] connection data to the queue error!",new_value->ip,new_value->username);
        }
      }
      else if(!strcasecmp(argv[1],"delete")) 
      {
        LOGINFO("exit status code: %d",OPENVPN_PLUGIN_CLIENT_DISCONNECT);
        VpnData *cleanvalue;
        char *ip = (char *)argv[2];
        if(ByValueLeaveVpnQueue(ConnVpnQueue_r,ip,&cleanvalue))
        {
          la_learn_roles_delete(cleanvalue);
          LOGINFO("Client [%s] is disconnect.IP [%s] ,current queue %d.",
                  cleanvalue->username,
                  cleanvalue->ip,
                  getVpnQueueLength(ConnVpnQueue_r));
          FreeConnVPNDataMem(cleanvalue);
        }
      }

    }
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
  }
  return res;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1 (openvpn_plugin_handle_t handle)
{
  ldap_context_t *context = (ldap_context_t *) handle;
  action_t *action = action_new( );

  if (DOINFO (context->verb))
    LOGINFO( "%s() called", __FUNCTION__ );
  if( action){
    action->type = LDAP_AUTH_ACTION_QUIT;
    action_push( context->action_list, action );
    if( DODEBUG( context->verb ) )
      LOGDEBUG ("Waiting for thread to return");
    if(action_thread !=0 )
      pthread_join( action_thread, NULL );
    if( DODEBUG( context->verb ) )
      LOGDEBUG ("Thread returned queries left in queue: %d", list_length( context->action_list ));
    pthread_attr_destroy( &action_thread_attr );
    pthread_mutex_destroy( &action_mutex );
    pthread_cond_destroy( &action_cond );
  }
  // 释放iptable规则
  LdapIptableRoles *tpl=((profile_config_t *)context->config->profiles->first->data)->iptable_rules;
  config_uninit_iptable_rules(tpl);
  if(DestroyVpnQueue(ConnVpnQueue_r))
    LOGINFO("free queue success.");
  ldap_context_free( context );
  config_ldap_plugin_free(iptblrules);
  config_ldap_plugin_free(ldapconfig);
  config_ldap_plugin_serverinfo_free(openvpnserverinfo);
  //pthread_exit(NULL); 
}

OPENVPN_EXPORT void
openvpn_plugin_abort_v1 (openvpn_plugin_handle_t handle)
{
  openvpn_plugin_close_v1(handle);
}

OPENVPN_EXPORT int
openvpn_plugin_select_initialization_point_v1 (void)
{
  // if(DODEBUG)
  // {
    LOGDEBUG("OPENVPN_PLUGIN_INIT_POST_UID_CHANGE");
  // }
  return OPENVPN_PLUGIN_INIT_POST_UID_CHANGE;
}

void *
action_thread_main_loop (void *c)
{
  ldap_context_t *context = c;
  action_t *action = NULL;
  int rc;

  int loop = 1;
  while( loop ){
    action = action_pop(context->action_list);
    /* handle action */
    if (action){
      switch (action->type){
        case LDAP_AUTH_ACTION_AUTH:
          if( DOINFO(context->verb ) ){
            LOGINFO ( "Authentication requested for user %s",
                      ((auth_context_t *)action->context)->username);
          }
          rc = la_ldap_handle_authentication( context, action );
          /* we need to write the result to  auth_control_file */
          if( DODEBUG(context->verb ) ){
            LOGDEBUG( "User %s: Writing %c to auth_control_file %s",
                          ((auth_context_t *)action->context)->username,
                          rc == OPENVPN_PLUGIN_FUNC_SUCCESS ? '1' : '0',
                          ((auth_context_t *)action->context)->auth_control_file);
          }
          write_to_auth_control_file ( ((auth_context_t *)action->context)->auth_control_file,
                                        rc == OPENVPN_PLUGIN_FUNC_SUCCESS ? '1' : '0');
          break;
        case LDAP_AUTH_ACTION_QUIT:
          if( DOINFO(context->verb ) ){
            LOGINFO( "Authentication thread received ACTION_QUIT");
          }
          loop = 0;
          break;
        default:
          LOGWARNING( "%s:%d %s() Unknown action %d", __FILE__, __LINE__, __FUNCTION__, action->type);
      }
      action_free( action );
    }
  }
  pthread_exit (NULL);
}

OPENVPN_EXPORT void *
openvpn_plugin_client_constructor_v1( openvpn_plugin_handle_t handle){
  client_context_t *cc = client_context_new( );
  return (void *)cc;
}

OPENVPN_EXPORT void
openvpn_plugin_client_destructor_v1( openvpn_plugin_handle_t handle, void *per_client_context ){
  client_context_t *cc = per_client_context;
  LOGINFO("The current user %s is disconnected from the server. userid: %s",cc->user_dn ,cc->user_id);
  client_context_free( cc );
}
