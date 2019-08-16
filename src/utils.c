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
  while(arr[i]!=NULL)
  {
    i++;
  }
  return i;
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
ldap_plugin_execve(const char * filename,char * const argv[ ],char * const envp[ ])
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
