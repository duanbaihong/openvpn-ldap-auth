/**
 * action.c
 * vim: tabstop=2 softtabstop=2 shiftwidth=2 expandtab
 * Copyright (C) 2009 Emmanuel Bretelle <chantra@debuntu.org>
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

#include "action.h"
#include "utils.h"


action_t *
action_new( )
{
  action_t *a = NULL;
  a = la_malloc( sizeof( action_t ) );
  if( a ){
    la_memset( a, 0, sizeof( action_t ) );
  }
  return a;
}

void
action_free( void *a)
{
  action_t *action = a;
  if( action ){
    if( action->context_free_func )
      action->context_free_func( action->context );
    la_free( action );
  }
}

/* forward declaration of main loop */


void action_push(list_t *list, action_t *action)
{
  pthread_mutex_lock(&action_mutex);
  if (action->type == LDAP_AUTH_ACTION_QUIT)
    list_prepend(list, (void *)action);
  else
    list_append(list, (void *)action);
  if (list_length(list) == 1)
  {
    pthread_cond_signal(&action_cond);
    LOGINFO("Sent signal to authenticating loop");
  }
  pthread_mutex_unlock(&action_mutex);
}

action_t *
action_pop(list_t *l)
{
  action_t *a = NULL;
  pthread_mutex_lock(&action_mutex);
  if (list_length(l) == 0)
  {
    pthread_cond_wait(&action_cond, &action_mutex);
  }
  /* get the action item */
  a = list_remove_item_at(l, 0);
  pthread_mutex_unlock(&action_mutex);
  return a;
}
