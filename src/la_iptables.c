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
    char *desc=vdata->groups[i].description!=NULL?vdata->groups[i].description:strcpy(cc->groups[i].description, "");
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
    char *desc=vdata->groups[i].description!=NULL?vdata->groups[i].description:strcpy(cc->groups[i].description, "");
    int len=strlen(IPT_RULES_FMT)+strlen(vdata->ip)+strlen(vdata->username)+strlen(vdata->groups[i].groupname)+strlen(desc);
    char rules_item[len];
    sprintf(rules_item,IPT_RULES_FMT,vdata->ip,vdata->groups[i].groupname,vdata->username,desc);
    ret=ldap_plugin_run_system(IPTABLE_DELETE_ROLE,"FORWARD",rules_item);
  }
  return ret;
}


static void config_default_iptable_rules(iptable_rules_action_type ctype)
{
  char allowVpn[128];
  sprintf(allowVpn,"-p %s -m %s --dport %s -j ACCEPT",openvpnserverinfo->proto,openvpnserverinfo->proto,openvpnserverinfo->serverport);
  ldap_plugin_run_system(ctype,"INPUT",allowVpn);
  // 添加FORWORD链默认规则 默认允许DNS解析，最后规则是拒绝所有连接。
  // char * netaddr=GetNetworkAndCIDRAddress(localip,localnetmask);
  sprintf(allowVpn, "-p all -s %s -j DROP", openvpnserverinfo->netaddr);
  ldap_plugin_run_system(ctype, "FORWARD", allowVpn);
  sprintf(allowVpn,"-p tcp -m tcp --dport 53 -s %s -j ACCEPT",openvpnserverinfo->netaddr);
  ldap_plugin_run_system(ctype,"FORWARD",allowVpn);
  sprintf(allowVpn,"-p udp -m udp --dport 53 -s %s -j ACCEPT",openvpnserverinfo->netaddr);
  sprintf(allowVpn,"-p udp -m udp --dport 53 -s %s -j ACCEPT",openvpnserverinfo->netaddr);
  ldap_plugin_run_system(ctype,"FORWARD",allowVpn);
  sprintf(allowVpn,"-s %s -j MASQUERADE",openvpnserverinfo->netaddr);
  if (ctype == IPTABLE_DELETE_ROLE)
  {
    ldap_plugin_run_system(IPTABLE_DELETE_MASQUERADE_ROLE, "POSTROUTING", allowVpn);
  }
  else if (ctype == IPTABLE_INSERT_ROLE)
    ldap_plugin_run_system(IPTABLE_INSERT_MASQUERADE_ROLE, "POSTROUTING", allowVpn);

}

void config_uninit_iptable_rules(LdapIptableRoles *rules)
{
  int i=0;
  // LOGINFO("%s",rules);
  if(!rules) return ;
  config_default_iptable_rules(IPTABLE_DELETE_ROLE);
  while (i <rules->clen)
  {
    if(rules->chains[i].chain_name!=NULL)
    {
      ldap_plugin_run_system(IPTABLE_EMPTY_FILTER,rules->chains[i].chain_name,"");
      ldap_plugin_run_system(IPTABLE_DELETE_FILTER,rules->chains[i].chain_name,"");
    }
    i++;
  } 
}

void config_init_iptable_rules(LdapIptableRoles *rules)
{
  LOGINFO("Starting Initial iptables policy entry。");
  config_default_iptable_rules(IPTABLE_INSERT_ROLE);
  for(int i=0;i<rules->clen;i++)
  {
    if(rules->chains[i].chain_name!=NULL)
    {
      int ret;
      ret =ldap_plugin_run_system(IPTABLE_CREATE_FILTER,rules->chains[i].chain_name,"");
      if(ret!=0)
      {
        i++;
        continue;
      }
      for(int m=0;m<rules->chains[i].rule_len;m++)
      {
        if(rules->chains[i].rule_item[m]!=NULL)
        {
          ldap_plugin_run_system(IPTABLE_APPEND_ROLE,rules->chains[i].chain_name,rules->chains[i].rule_item[m]);
        }
      }
      ldap_plugin_run_system(IPTABLE_APPEND_ROLE,rules->chains[i].chain_name,"-p all -j RETURN");
    }
  }
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
      LOGERROR("Run command error:[ %s %s %s] msg:%s,error code=%d",
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

// 
void config_iptables_printf(LdapIptableRoles *rules)
{
  if(!rules) return;
  LOGNOTICE("============================IptablesRoles============================");
  for(int i=0; i<rules->clen;i++)
  {
    LOGNOTICE("%d,%s:",i,rules->chains[i].chain_name);
    for(int s=0; s<rules->chains[i].rule_len;s++)
    {
      LOGNOTICE("\t%d-%d-%s",s,rules->chains[i].rule_len,rules->chains[i].rule_item[s]);
    }
  }
}