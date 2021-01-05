#include "utils.h"
#include <stdio.h>
#include <string.h>
// #include <fcntl.h>
// #include <termios.h>
// #include <stdarg.h>
#include "debug.h"
// #include <sys/types.h>
// #include <sys/wait.h>
// #include <unistd.h>
#include <errno.h> 
#include <queue.h>
#include "client_context.h"
#include "la_iptables.h"

const char *IPT_RULES_FMT="-p all -s %s -j %s -m comment --comment 'User [%s]=>[%s]'";

// 添加规则
int la_learn_roles_add(VpnData *vdata)
{
  int ret=-1;
  for(int i=0;i<vdata->group_len;i++ )
  {
    char *desc=vdata->groups[i].description!=NULL?vdata->groups[i].description:"\0";
    int len=strlen(IPT_RULES_FMT)+strlen(vdata->ip)+strlen(vdata->username)+strlen(vdata->groups[i].groupname)+strlen(desc);
    char rules_item[len];
    sprintf(rules_item,IPT_RULES_FMT,vdata->ip,vdata->groups[i].groupname,vdata->username,desc);
    ret=ldap_plugin_run_system(IPTABLE_INSERT_ROLE,"FORWARD",rules_item);
    LOGINFO("Client [%s] is connected.IP [%s],vpn groups [%s]!",
            vdata->username,
            vdata->ip,
            vdata->groups[i].groupname);
  }
  return ret;
}

// 删除规则
int la_learn_roles_delete(VpnData *vdata)
{
  int ret=-1;
  for(int i=0;i<vdata->group_len;i++)
  {
    int len=strlen(IPT_RULES_FMT)+strlen(vdata->ip)+strlen(vdata->username)+strlen(vdata->groups[i].groupname)+strlen(vdata->groups[i].description);
    char rules_item[len];
    sprintf(rules_item,IPT_RULES_FMT,vdata->ip,vdata->groups[i].groupname,vdata->username,vdata->groups[i].description);
    ret=ldap_plugin_run_system(IPTABLE_DELETE_ROLE,"FORWARD",rules_item);
  }
  return ret;
}

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
    case IPTABLE_INSERT_MASQUERADE_ROLE:
      iptables_cmd="/sbin/iptables -t nat -I";
      sprintf(cmd_argv,"%s %s %s %s",filename,iptables_cmd,filter_name,rule_item);
      break;
    case IPTABLE_DELETE_MASQUERADE_ROLE:
      iptables_cmd="/sbin/iptables -t nat -D";
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