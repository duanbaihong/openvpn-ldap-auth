/**
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 *
 * openvpn-ldap-auth-test.c
 * OpenVPN LDAP Authentication Plugin Test Driver
 *
 * Copyright (c) 2005 Landon Fuller <landonf@threerings.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Landon Fuller nor the names of any contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <openvpn-plugin.h>
#include <sys/types.h>
#include <unistd.h>

#define SLEEP_TIME 1

const char username_template[] = "username=";
const char password_template[] = "password=";
void **client_contexts = NULL;
struct openvpn_plugin_string_list *return_list = NULL;

int main(int argc, const char *argv[]) {
	openvpn_plugin_handle_t handle;
	unsigned int type;
	const char *envp[7]; /* username, password, verb, ifconfig_pool_remote_ip, auth_confrol_file, [pf_file], NULL */
	char username[30];
	char *password;
	int loops;
	int err;
  pid_t pid = getpid();
  char command[100];


	/* Grab username and password */
	printf("Username: ");
	if(!scanf("%s", username)){
    fprintf(stderr, "Could not read username\n");
    return 1;
  }

	password = getpass("Password: ");

  printf("Number of authentication loops: ");
  if(!scanf("%d", &loops)){
    fprintf(stderr, "Could not read loops number\n");
    return 1;
  }

	/* Set up username and password */
	envp[0] = malloc(sizeof(username_template) + strlen(username));
	strcpy((char *) envp[0], username_template);
	strcat((char *) envp[0], username);

	envp[1] = malloc(sizeof(password_template) + strlen(password));
	strcpy((char *) envp[1], password_template);
	strcat((char *) envp[1], password);
  free( password );
	/* Remote Pool IP */
	envp[2] = "ifconfig_pool_remote_ip=10.0.50.1";
  envp[3] = "verb=4";
  envp[4] = "auth_control_file=/tmp/foobar_ctrl_file.txt";

	handle = openvpn_plugin_open_v2(&type, argv, envp, NULL);

	if (!handle)
		errx(1, "Initialization Failed!\n");

  if( type & OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_ENABLE_PF) ){
    envp[5] = "pf_file=/tmp/foobar_pf_file.txt";
    envp[6] = NULL;
  }else{
	  envp[5] = NULL;
  }

  client_contexts = malloc( sizeof( void * ) * loops );
  if( client_contexts == NULL ){
    fprintf(stderr, "Could not allocate client contexts\n");
    return 1;
  }

  int i;
	/* Authenticate */
  for( i = 0; i < loops; i++ ){
    client_contexts[i] = openvpn_plugin_client_constructor_v1( handle );
    if( type & OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_ENABLE_PF) ){
      err = openvpn_plugin_func_v2(handle, OPENVPN_PLUGIN_ENABLE_PF, argv, envp, client_contexts[i], NULL);
      printf("Enable PF: %s\n", err == OPENVPN_PLUGIN_FUNC_SUCCESS ? "True" : "False" );
    }else{
        printf("Enable PF: Not enabled\n");
    }
    err = openvpn_plugin_func_v2(handle, OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY, argv, envp, client_contexts[i], NULL);
    if (err == OPENVPN_PLUGIN_FUNC_ERROR) {
      printf("Authorization Failed!\n");
    } else if( err == OPENVPN_PLUGIN_FUNC_SUCCESS ) {
      printf("Authorization Succeed!\n");
    }else if ( err == OPENVPN_PLUGIN_FUNC_DEFERRED ){
      printf("Authorization Deferred!\n");
    }
    printf( "Sleeping %d seconds to let the threads do some job...\n", SLEEP_TIME );
    sleep( SLEEP_TIME + 2 );
    //goto free_exit;
    /* Client Connect */
    err = openvpn_plugin_func_v2(handle, OPENVPN_PLUGIN_CLIENT_CONNECT_V2, argv, envp, client_contexts[i], &return_list);
    if (err != OPENVPN_PLUGIN_FUNC_SUCCESS) {
      printf("client-connect failed!\n");
    } else {
      printf("client-connect succeed!\n");
      printf("Config returned by plugin: %s\n", return_list ? return_list->value : "Nothing");
    }

    struct openvpn_plugin_string_list *rl, *next;
    next = return_list;
    while( next ){
      free( next->name);
      free( next->value);
      rl = next;
      next = next->next;
      free( rl );
      rl = NULL;
    }
    /* Client Disconnect */
    err = openvpn_plugin_func_v2(handle, OPENVPN_PLUGIN_CLIENT_DISCONNECT, argv, envp, client_contexts[i], NULL);
    if (err != OPENVPN_PLUGIN_FUNC_SUCCESS) {
      printf("client-disconnect failed!\n");
    } else {
      printf("client-disconnect succeed!\n");
    }
  //free_exit:
    openvpn_plugin_client_destructor_v1( handle, client_contexts[i] );
  }

  free( client_contexts );
  sprintf(command, "lsof -n -p %d", pid);
  //system(command);
	openvpn_plugin_close_v1(handle);
  printf( "Sleeping %d seconds...\n", SLEEP_TIME );
  sleep( SLEEP_TIME );
	free((char *) envp[0]);
	free((char *) envp[1]);

	exit (0);
}
