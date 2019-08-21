/**
 * vim: tabstop=2:shiftwidth=2:softtabstop=2:expandtab
 * utils.c
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
 *
 */

#include "utils.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <stdarg.h>
#include "debug.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h> 

#define BACKSPACE 127

void *
la_malloc( size_t size ){
  return malloc( size );
}

void
la_free( void *ptr ){
  free( ptr );
}

void *
la_memset( void *s, int c, size_t n ){
  return memset( s, c, n );
}


int ldap_array_len(char *arr[])
{
  int i=0;
  if(arr) {
    while(arr[i]!=NULL)
    {
      i++;
    }
  }
  return i;
}
/*
 * Return the length of a string array
 */
int
string_array_len(const char *array[])
{
  int i = 0;
  if (array)
  {
    while (array[i])
      ++i;
  }
  return i;
}

/*
 * Given an environmental variable name, search
 * the envp array for its value, returning it
 * if found or NULL otherwise.
 */
const char *
get_env(const char *name, const char *envp[])
{
  if (envp)
  {
    int i;
    const int namelen = strlen(name);
    for (i = 0; envp[i]; ++i)
    {
      if (!strncmp(envp[i], name, namelen))
      {
        const char *cp = envp[i] + namelen;
        if (*cp == '=')
          return cp + 1;
      }
    }
  }
  return NULL;
}

/**
 * same as strdup but given a va_list
 */
char *
vstrdupf (const char *fmt, va_list vargs){
  char     buf[BUFSIZ];
  char    *p;

  if (!fmt) {
    return (NULL);
  }
  vsnprintf (buf, sizeof (buf), fmt, vargs);

  buf[sizeof (buf) - 1] = '\0';        /* ensure buf is NUL-terminated */

  if (!(p = strdup (buf))) {
    return (NULL);
  }
  return (p);
}


char *
strdupf (const char *fmt, ...){
  va_list  vargs;
  char    *p;

  if (!fmt) {
    return (NULL);
  }
  va_start (vargs, fmt);
  p = vstrdupf (fmt, vargs);
  va_end (vargs);

  return p;
}

char *
strcatf( char *dest, const char *fmt, ...){
  va_list  vargs;
  char    *p;
  if (!fmt) {
    return dest;
  }
  va_start (vargs, fmt);
  p = vstrdupf( fmt, vargs );
  va_end (vargs);

  if(p){
    strcat( dest, p );
    la_free( p );
  }
  return dest;
}

char *
str_replace( const char *string, const char *substr, const char *replacement ){
  char *tok = NULL;
  char *newstr = NULL;

  tok = strstr( string, substr );
  if( tok == NULL ) return strdup( string );
  newstr = malloc( strlen( string ) - strlen( substr ) + strlen( replacement ) + 1 );
  if( newstr == NULL ) return NULL;
  memcpy( newstr, string, tok - string );
  memcpy( newstr + (tok - string), replacement, strlen( replacement ) );
  memcpy( newstr + (tok - string) + strlen( replacement ), tok + strlen( substr ), strlen( string ) - strlen( substr ) - ( tok - string ) );
  memset( newstr + strlen( string ) - strlen( substr ) + strlen( replacement ) , 0, 1 );
  return newstr;
}

char *
str_replace_all ( const char *string, const char *substr, const char *replacement ){
  char *tok = NULL;
  char *newstr = NULL;
  char *oldstr = NULL;
  char *head = NULL;

  /* if either substr or replacement is NULL, duplicate string a let caller
 * handle it */
  if ( substr == NULL || replacement == NULL ) return strdup (string);
  newstr = strdup (string);
  head = newstr;
  while ( (tok = strstr ( head, substr ))){
    oldstr = newstr;
    newstr = malloc ( strlen ( oldstr ) - strlen ( substr ) + strlen ( replacement ) + 1 );
    /*failed to alloc mem, free old string and return NULL */
    if ( newstr == NULL ){
      free (oldstr);
      return NULL;
    }
    memcpy ( newstr, oldstr, tok - oldstr );
    memcpy ( newstr + (tok - oldstr), replacement, strlen ( replacement ) );
    memcpy ( newstr + (tok - oldstr) + strlen( replacement ), tok + strlen ( substr ), strlen ( oldstr ) - strlen ( substr ) - ( tok - oldstr ) );
    memset ( newstr + strlen ( oldstr ) - strlen ( substr ) + strlen ( replacement ) , 0, 1 );
    /* move back head right after the last replacement */
    head = newstr + (tok - oldstr) + strlen( replacement );
    free (oldstr);
  }
  return newstr;
}

char *get_passwd( const char *prompt ){
	struct termios old, new;
	int size = 0;
	char c;
	char *pass = malloc( size + 1 );
	/* turn off echoing */
	if (tcgetattr (fileno (stdin), &old) != 0 )
        return NULL;
	new = old;
	//new.c_lflag &= ~ECHO || ECHOCTL;
	new.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL | ICANON);
	if (tcsetattr (fileno ( stdin ), TCSAFLUSH, &new ) != 0 )
		return NULL;
	/* get the password */
	if( prompt ) fprintf( stdout, "%s", prompt );
	while( ( c = getc( stdin )) != '\n' ){
		if( c == BACKSPACE ){
			/* never happens as getc only read once \n is entered */
			if( size > 0 ) size--;
		}else{
			size ++;
			pass = realloc( pass, size + 1);
			*(pass+size-1) = c;
		}
	}
	*(pass+size) = '\0';
	/* Restore terminal. */
	tcsetattr (fileno ( stdin ), TCSAFLUSH, &old );
#if 0
	fprintf(stdout, "Password size: %d, strlen %d\n", size, strlen(pass) );
#endif
	return pass;
}


/*
 * Run execve() inside a fork().  Designed to replicate the semantics of system() but
 * in a safer way that doesn't require the invocation of a shell or the risks
 * assocated with formatting and parsing a command line.
 */
int
ldap_plugin_execve(const char * filename,char * argv[ ],char * envp[ ])
{
    int ret = -1;
    if (filename)
    {
// #if defined(ENABLE_FEATURE_EXECVE)
      pid_t pid;

      pid = fork();
      if (pid == (pid_t)0) /* child side */
      {
        LOGINFO("ldap_plugin_execve run command at pid=%d: %s.",(int) pid,filename );
        LOGINFO("RUN CMD: %s",char_array_join(argv," "));
        execve(filename, argv, envp);
        if(errno!=0){
          LOGERROR("Run command error:%s,error code=%d",strerror(errno),errno);
        }
        exit(127);
      }
      else if (pid < (pid_t)0) /* fork failed */
      {
        LOGERROR("ldap_plugin_execve: unable to fork");
      }
      else /* parent side */
      {
        if (waitpid(pid, &ret, 0) != pid)
        {
          ret = -1;
        }
      }
// #else  /* if defined(ENABLE_FEATURE_EXECVE) */
    // LOGWARNING("ldap_plugin_execve: execve function not available");
// #endif /* if defined(ENABLE_FEATURE_EXECVE) */
    }
    else
    {
      LOGWARNING("ldap_plugin_execve: called with empty argv");
    }

    return ret;
}

char * 
char_array_join(char *arr[],char *flag)
{
  int i=0;
  char *m;
  int len=0;
  while(arr[i]!= NULL)
  {
    len+=strlen(arr[i++])+strlen(flag);
  }
  len++;
  i=0;
  m=malloc(len);
  memset(m,0,len);
  if(!flag) flag=",";
  while(arr[i]!=NULL)
  {
    if(i>0) strcat(m,flag);
    strcat(m,arr[i++]);
  }
  return m;
}

// char * string_split(char *str,char *s_flag)
// {
//   char *newarr;
//   newarr=(char *)malloc(sizeof(char)*256);
//   char * p;
//   p = strtok(str,s_flag);
//   int i=0;
//   if (p==NULL)
//   do
//   {
//     if(i>254)
//     {
//       // LOGERROR("Rule entries [%s] exceed 255 space limits",str);
//       break;
//     }
//     newarr[i++]=strdup(p);
    
//   }while((p=strtok(NULL,s_flag))!=NULL);
//   return newarr;
// }

int
ldap_plugin_run_system(iptable_rules_action_type cmd_type,char * filter_name, char * rule_item)
{
  int ret = -1;
  if(!filter_name) return ret;
  char * filename="/usr/bin/sudo -u root";
  char * cmd_argv;
  char * iptables_cmd="/sbin/iptables -N";
  int len=strlen(filename)+strlen(iptables_cmd)+strlen(filter_name)+strlen(rule_item)+4;
  cmd_argv=malloc(len);
  memset(cmd_argv,0,len);
  switch (cmd_type)
  {
    case IPTABLE_CREATE_FILTER:
      iptables_cmd="/sbin/iptables -N";
      sprintf(cmd_argv,"%s %s %s",filename,iptables_cmd,filter_name);
      break;
    case IPTABLE_EMPTY_FILTER:
      iptables_cmd="/sbin/iptables -F";
      sprintf(cmd_argv,"%s %s %s",filename,iptables_cmd,filter_name);
      break;
    case IPTABLE_DELETE_FILTER:
      iptables_cmd="/sbin/iptables -X";
      sprintf(cmd_argv,"%s %s %s",filename,iptables_cmd,filter_name);
      break;
    case IPTABLE_APPEND_ROLE:
      iptables_cmd="/sbin/iptables -A";
      sprintf(cmd_argv,"%s %s %s %s",filename,iptables_cmd,filter_name,rule_item);
      break;
    case IPTABLE_INSERT_ROLE:
      iptables_cmd="/sbin/iptables -I";
      sprintf(cmd_argv,"%s %s %s %s",filename,iptables_cmd,filter_name,rule_item);
      break;
    case IPTABLE_DELETE_ROLE:
      iptables_cmd="/sbin/iptables -D";
      sprintf(cmd_argv,"%s %s %s %s",filename,iptables_cmd,filter_name,rule_item);
      break;
    default:
      break;
  }
  if(cmd_argv)
  {
    ret=system(cmd_argv);
    if(ret){
      LOGERROR("Run command error:[%s %s %s] msg:%s,error code=%d",
        iptables_cmd,
        filter_name,
        rule_item,
        strerror(errno),
        errno);
    }else{
      LOGINFO("RUN CMD: %s %s %s. return code=%d",iptables_cmd,filter_name,rule_item,ret);
    }
    FREE_IF_NOT_NULL(cmd_argv);
  }
  return ret;
}

// netmask to cidr
unsigned short NetmaskToCidr(const char* netmask)
{
  unsigned short cidr;
  int netmask_s[4];
  int ipbit=-1;
  cidr=0;
  ipbit=sscanf(netmask, "%d.%d.%d.%d", &netmask_s[0], &netmask_s[1], &netmask_s[2], &netmask_s[3]);
  if(ipbit<4)
  {
    LOGERROR("Unlawful Subnet Mask Format %s,normal format: xxx.xxx.xxx.xxx;",netmask);
    return 0;
  }
  for (int i=0; i<4; i++)
  {
    switch(netmask_s[i])
    {
      case 0x80:
        cidr+=1;
        break;
      case 0xC0:
        cidr+=2;
        break;
      case 0xE0:
        cidr+=3;
        break;
      case 0xF0:
        cidr+=4;
        break;
      case 0xF8:
        cidr+=5;
        break;
      case 0xFC:
        cidr+=6;
        break;
      case 0xFE:
        cidr+=7;
        break;
      case 0xFF:
        cidr+=8;
        break;
      default:
        return cidr;
        break;
    }
  }
  return cidr;
}
char * GetNetworkAddress(const char* ipaddress,const char* netmask)
{
  int ipaddress_new[4];
  int netmask_new[4];
  char *b;
  b=malloc(16);
  memset(b,0,16);
  sscanf(ipaddress, "%d.%d.%d.%d", &ipaddress_new[0], &ipaddress_new[1], &ipaddress_new[2], &ipaddress_new[3]);
  sscanf(netmask, "%d.%d.%d.%d", &netmask_new[0], &netmask_new[1], &netmask_new[2], &netmask_new[3]);

  sprintf(b,"%d.%d.%d.%d",
    ipaddress_new[0]&netmask_new[0],
    ipaddress_new[1]&netmask_new[1],
    ipaddress_new[2]&netmask_new[2],
    ipaddress_new[3]&netmask_new[3]);
  return b;
}

const char * GetNetworkAndCIDRAddress(const char* ipaddress,const char* netmask)
{
  char *netaddr;
  char *b;
  b=malloc(19);
  memset(b,0,19);
  netaddr=GetNetworkAddress(ipaddress,netmask);
  sprintf(b,"%s/%d",netaddr,NetmaskToCidr(netmask));
  check_and_free(netaddr);
  return b;
}


// #if 0
/*
 * Given an environmental variable name, dumps
 * the envp array values.
 */

void dump_env (const char *envp[])
{

  fprintf (stderr, "//START of dump_env\\\\\n");
  if (envp){
    int i;
    for (i = 0; envp[i]; ++i)
      fprintf (stderr, "%s\n", envp[i]);
  }
  fprintf (stderr, "//END of dump_env\\\\\n");
}
// #endif

/* write a value to auth_control_file */
int
write_to_auth_control_file( char *auth_control_file, char value )
{
  int fd, rc;
  int err = 0;
  fd = open( auth_control_file, O_WRONLY | O_CREAT, 0700 );
  if( fd == -1 ){
    LOGERROR( "Could not open file auth_control_file %s: %s", auth_control_file, strerror( errno ) );
    return -1;
  }
  rc = write( fd, &value, 1 );
  if( rc == -1 ){
    LOGERROR( "Could not write value %c to auth_control_file %s: %s", value, auth_control_file, strerror( errno ) );
    err = 1;
  }else if( rc !=1 ){
    LOGERROR( "Could not write value %c to auth_control_file %s", value, auth_control_file );
    err = 1;
  }
  rc = close( fd );
  if( rc != 0 ){
    LOGERROR( "Could not close file auth_control_file %s: %s", auth_control_file, strerror( errno ) );
  }
  /* Give the user a hind on why it potentially failed */
  if( err != 0)
    LOGERROR( "Is *tmp-dir* set up correctly in openvpn config?");
  return rc == 0;
}


void check_and_free( void *d )
{
	if( d ) la_free( d );
}