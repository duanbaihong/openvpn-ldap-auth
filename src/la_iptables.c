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
#include <unistd.h>
#include <queue.h>
#include "client_context.h"
#include "la_ldap.h"
#include "la_iptables.h"

const char *IPT_RULES_FMT="-p all -s %s -j %s -m comment --comment 'User [%s]=>[%s]'";

// 添加规则
int la_learn_roles_add(VpnData *vdata)
{
  int ret=-1;
  for(int i=0;i<vdata->group_len;i++ )
  {
    char *desc=vdata->groups[i].description!=NULL?vdata->groups[i].description:"";
    // 检查必要的指针是否为NULL
    if (!vdata->ip || !vdata->username || !vdata->groups[i].groupname) {
        LOGERROR("Invalid parameters for group %d", i);
        ret = -1;
        continue;
    }
    // 计算所需缓冲区大小，+1 用于空终止符
    int len = snprintf(NULL, 0, IPT_RULES_FMT, 
                      vdata->ip, 
                      vdata->groups[i].groupname, 
                      vdata->username, 
                      desc) + 1;
    char  rules_item[len];
    // 格式化字符串
    snprintf(rules_item, len, IPT_RULES_FMT,
            vdata->ip,
            vdata->groups[i].groupname,
            vdata->username,
            desc);
    
    int cmd_ret=ldap_plugin_run_system(IPTABLE_INSERT_ROLE,"FORWARD",rules_item);
    if (cmd_ret != 0) {
      LOGERROR("Failed to add rule for group %s,%s", vdata->groups[i].groupname,rules_item);
      ret=cmd_ret;
    }else{
      LOGINFO("Client [%s] is connected.IP [%s],vpn groups [%s]!",
            vdata->username,
            vdata->ip,
            vdata->groups[i].groupname);
    }
  }
  return ret;
}

// 删除规则
int la_learn_roles_delete(VpnData *vdata)
{
  int ret=-1;
  for(int i=0;i<vdata->group_len;i++)
  {
    char *desc=vdata->groups[i].description!=NULL?vdata->groups[i].description:"";
    // 检查必要的指针是否为NULL
    if (!vdata->ip || !vdata->username || !vdata->groups[i].groupname) {
        LOGERROR("Invalid parameters for group %d", i);
        ret = -1;
        continue;
    }
    // 计算所需缓冲区大小，+1 用于空终止符
    int len = snprintf(NULL, 0, 
        IPT_RULES_FMT, 
        vdata->ip, 
        vdata->groups[i].groupname, 
        vdata->username, 
        desc) + 1;
    // int len=strlen(IPT_RULES_FMT)+strlen(vdata->ip)+strlen(vdata->username)+strlen(vdata->groups[i].groupname)+strlen(desc);
    char rules_item[len];
    // snprintf(rules_item,IPT_RULES_FMT,vdata->ip,vdata->groups[i].groupname,vdata->username,desc);
    // 格式化字符串
    snprintf(rules_item, len, 
        IPT_RULES_FMT,
        vdata->ip,
        vdata->groups[i].groupname,
        vdata->username,
        desc);
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
  int ret = -1,len;
  if(!filter_name) return ret;
  char * filename;
  if( geteuid() == 0 ){
    filename = "";
  }else{
    filename = "/usr/bin/sudo -u root";
  }
  char * cmd_argv = NULL;
  char * iptables_cmd="/sbin/iptables -N";
  // int len=strlen(filename)+strlen(iptables_cmd)+strlen(filter_name)+strlen(rule_item)+4;
  switch (cmd_type)
  {
    case IPTABLE_CREATE_FILTER:
      iptables_cmd="/sbin/iptables -N";
      len=snprintf(NULL,0,"%s %s %s",filename,iptables_cmd,filter_name)+1;
      cmd_argv=la_malloc(len);
      snprintf(cmd_argv,len,"%s %s %s",filename,iptables_cmd,filter_name);
      break;
    case IPTABLE_EMPTY_FILTER:
      iptables_cmd="/sbin/iptables -F";
      len=snprintf(NULL,0,"%s %s %s",filename,iptables_cmd,filter_name)+1;
      cmd_argv=la_malloc(len);
      snprintf(cmd_argv,len,"%s %s %s",filename,iptables_cmd,filter_name);
      break;
    case IPTABLE_DELETE_FILTER:
      iptables_cmd="/sbin/iptables -X";
      len=snprintf(NULL,0,"%s %s %s",filename,iptables_cmd,filter_name)+1;
      cmd_argv=la_malloc(len);
      snprintf(cmd_argv,len,"%s %s %s",filename,iptables_cmd,filter_name);
      break;
    case IPTABLE_APPEND_ROLE:
      iptables_cmd="/sbin/iptables -A";
      len=snprintf(NULL,0,"%s %s %s %s",filename,iptables_cmd,filter_name,rule_item)+1;
      cmd_argv=la_malloc(len);
      snprintf(cmd_argv,len,"%s %s %s %s",filename,iptables_cmd,filter_name,rule_item);
      break;
    case IPTABLE_INSERT_ROLE:
      iptables_cmd="/sbin/iptables -I";
      len=snprintf(NULL,0,"%s %s %s %s",filename,iptables_cmd,filter_name,rule_item)+1;
      cmd_argv=la_malloc(len);
      snprintf(cmd_argv,len,"%s %s %s %s",filename,iptables_cmd,filter_name,rule_item);
      break;
    case IPTABLE_DELETE_ROLE:
      iptables_cmd="/sbin/iptables -D";
      len=snprintf(NULL,0,"%s %s %s %s",filename,iptables_cmd,filter_name,rule_item)+1;
      cmd_argv=la_malloc(len);
      snprintf(cmd_argv,len,"%s %s %s %s",filename,iptables_cmd,filter_name,rule_item);
      break;
    case IPTABLE_INSERT_MASQUERADE_ROLE:
      iptables_cmd="/sbin/iptables -t nat -I";
      len=snprintf(NULL,0,"%s %s %s %s",filename,iptables_cmd,filter_name,rule_item)+1;
      cmd_argv=la_malloc(len);
      snprintf(cmd_argv,len,"%s %s %s %s",filename,iptables_cmd,filter_name,rule_item);
      break;
    case IPTABLE_DELETE_MASQUERADE_ROLE:
      iptables_cmd="/sbin/iptables -t nat -D";
      len=snprintf(NULL,0,"%s %s %s %s",filename,iptables_cmd,filter_name,rule_item)+1;
      cmd_argv=la_malloc(len);
      snprintf(cmd_argv,len,"%s %s %s %s",filename,iptables_cmd,filter_name,rule_item);
      break;
    case IPTABLE_INSERT_ROLE_AT:
      iptables_cmd="/sbin/iptables -I";
      /* rule_item 格式: "INDEX RULE_CONTENT"，如 "2 -p tcp --dport 443 -j ACCEPT" */
      len=snprintf(NULL,0,"%s %s %s %s",filename,iptables_cmd,filter_name,rule_item)+1;
      cmd_argv=la_malloc(len);
      snprintf(cmd_argv,len,"%s %s %s %s",filename,iptables_cmd,filter_name,rule_item);
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
      if(geteuid() != 0){
        LOGNOTICE("HINT: Add the following to /etc/sudoers (run visudo):");
        LOGNOTICE("  openvpn    ALL=(ALL)    NOPASSWD:/sbin/iptables");
      }
    }else{
      LOGINFO("RUN CMD: %s %s %s. return code=%d",iptables_cmd,filter_name,rule_item,ret);
    }
    FREE_IF_NOT_NULL(cmd_argv);
  }
  return ret;
}

/* --- 动态加载 iptables 策略 --- */
pthread_t g_iptables_monitor_thread = 0;
volatile int g_iptables_monitor_running = 0;

static int chain_find(LdapIptableRoles *rules, const char *name) {
    for (int i = 0; i < rules->clen; i++)
        if (!strcmp(rules->chains[i].chain_name, name))
            return i;
    return -1;
}

static void update_chain_rules(char *name, IptableChainItems *old, IptableChainItems *new) {
    int min_len = old->rule_len < new->rule_len ? old->rule_len : new->rule_len;
    int changed = (old->rule_len != new->rule_len);
    if (!changed) {
        for (int m = 0; m < min_len; m++) {
            if (strcmp(old->rule_item[m], new->rule_item[m]) != 0) {
                changed = 1;
                break;
            }
        }
    }
    if (!changed) {
        LOGDEBUG("iptables reload: chain %s unchanged, skip", name);
        return;
    }

    LOGINFO("iptables reload: update chain %s (%d rules -> %d)",
            name, old->rule_len, new->rule_len);

    if (old->rule_len == new->rule_len) {
        /* 数量相同 → 用 -I INDEX 精确替换，不动 RETURN */
        int all_same = 1;
        for (int m = 0; m < min_len; m++)
            if (strcmp(old->rule_item[m], new->rule_item[m]) != 0) { all_same = 0; break; }
        if (all_same) return;  /* 完全没变，跳过 */

        for (int m = min_len - 1; m >= 0; m--)
            if (strcmp(old->rule_item[m], new->rule_item[m]) != 0)
                ldap_plugin_run_system(IPTABLE_DELETE_ROLE, name, old->rule_item[m]);

        for (int m = 0; m < min_len; m++)
            if (strcmp(old->rule_item[m], new->rule_item[m]) != 0) {
                char rule_with_pos[512];
                snprintf(rule_with_pos, sizeof(rule_with_pos), "%d %s", m + 1, new->rule_item[m]);
                ldap_plugin_run_system(IPTABLE_INSERT_ROLE_AT, name, rule_with_pos);
            }
    } else {
        /* 数量不同 → 删 RETURN → 删旧加新 → 加 RETURN */
        ldap_plugin_run_system(IPTABLE_DELETE_ROLE, name, "-p all -j RETURN");
        for (int m = 0; m < old->rule_len; m++) {
            int keep = 0;
            for (int n = 0; n < new->rule_len && !keep; n++)
                if (!strcmp(old->rule_item[m], new->rule_item[n])) keep = 1;
            if (!keep)
                ldap_plugin_run_system(IPTABLE_DELETE_ROLE, name, old->rule_item[m]);
        }
        for (int n = 0; n < new->rule_len; n++) {
            int exist = 0;
            for (int m = 0; m < old->rule_len && !exist; m++)
                if (!strcmp(new->rule_item[n], old->rule_item[m])) exist = 1;
            if (!exist)
                ldap_plugin_run_system(IPTABLE_APPEND_ROLE, name, new->rule_item[n]);
        }
        ldap_plugin_run_system(IPTABLE_APPEND_ROLE, name, "-p all -j RETURN");
    }
}

static void rebuild_online_forwards(const char *chain_name) {
    if (!ConnVpnQueue_r) return;
    for (ConnNode *n = ConnVpnQueue_r->front->next; n; n = n->next) {
        VpnData *d = n->data;
        for (int j = 0; j < d->group_len; j++) {
            if (!strcmp(d->groups[j].groupname, chain_name)) {
                int len = snprintf(NULL, 0, IPT_RULES_FMT, d->ip, chain_name, d->username, "") + 1;
                char rule[len];
                snprintf(rule, len, IPT_RULES_FMT, d->ip, chain_name, d->username, "");
                ldap_plugin_run_system(IPTABLE_INSERT_ROLE, "FORWARD", rule);
                break;
            }
        }
    }
}

static void drop_online_forwards(const char *chain_name) {
    if (!ConnVpnQueue_r) return;
    for (ConnNode *n = ConnVpnQueue_r->front->next; n; n = n->next) {
        VpnData *d = n->data;
        for (int j = 0; j < d->group_len; j++) {
            if (!strcmp(d->groups[j].groupname, chain_name)) {
                char *desc = d->groups[j].description ? d->groups[j].description : "";
                int len = snprintf(NULL, 0, IPT_RULES_FMT, d->ip, chain_name, d->username, desc) + 1;
                char rule[len];
                snprintf(rule, len, IPT_RULES_FMT, d->ip, chain_name, d->username, desc);
                ldap_plugin_run_system(IPTABLE_DELETE_ROLE, "FORWARD", rule);
                break;
            }
        }
    }
}

int la_iptables_reload(ldap_context_t *l) {
    profile_config_t *lp = l->config->profiles->first->data;
    LdapIptableRoles *old_rules = lp->iptable_rules;

    LdapIptableRoles *saved = lp->iptable_rules;
    int ret = config_load_ldap_groups_profiles(l);
    LdapIptableRoles *new_rules = lp->iptable_rules;
    if (ret != 0 || !new_rules) {
        lp->iptable_rules = saved;
        return -1;
    }
    lp->iptable_rules = saved;
    config_iptable_role_merge(new_rules, iptblrules);

    pthread_mutex_lock(&action_mutex);

    for (int i = 0; i < old_rules->clen; i++) {
        char *name = old_rules->chains[i].chain_name;
        if (chain_find(new_rules, name) >= 0) continue;
        LOGINFO("iptables reload: delete chain %s", name);
        drop_online_forwards(name);
        ldap_plugin_run_system(IPTABLE_EMPTY_FILTER, name, "");
        ldap_plugin_run_system(IPTABLE_DELETE_FILTER, name, "");
    }

    for (int i = 0; i < new_rules->clen; i++) {
        char *name = new_rules->chains[i].chain_name;
        int old_idx = chain_find(old_rules, name);
        if (old_idx < 0) {
            LOGINFO("iptables reload: create chain %s", name);
            ldap_plugin_run_system(IPTABLE_CREATE_FILTER, name, "");
            for (int m = 0; m < new_rules->chains[i].rule_len; m++)
                ldap_plugin_run_system(IPTABLE_APPEND_ROLE, name, new_rules->chains[i].rule_item[m]);
            ldap_plugin_run_system(IPTABLE_APPEND_ROLE, name, "-p all -j RETURN");
            rebuild_online_forwards(name);
        } else {
            update_chain_rules(name, &old_rules->chains[old_idx], &new_rules->chains[i]);
        }
    }

    lp->iptable_rules = new_rules;
    ldap_iptables_roles_free(old_rules);
    config_iptables_printf(new_rules);

    la_tc_reload(l);

    pthread_mutex_unlock(&action_mutex);
    LOGINFO("iptables rules reloaded: %d chains", new_rules->clen);
    return 0;
}

static void *iptables_monitor_thread(void *arg) {
    ldap_context_t *l = (ldap_context_t *)arg;
    g_iptables_monitor_running = 1;
    LOGINFO("iptables monitor thread started");
    while (g_iptables_monitor_running) {
        sleep(60);
        if (!g_iptables_monitor_running) break;
        la_iptables_reload(l);
    }
    g_iptables_monitor_running = 0;
    return NULL;
}

int la_iptables_start_monitor(ldap_context_t *l) {
    if (g_iptables_monitor_thread != 0) return 0;
    return pthread_create(&g_iptables_monitor_thread, NULL, iptables_monitor_thread, l);
}

void la_iptables_stop_monitor(void) {
    if (g_iptables_monitor_thread == 0) return;
    g_iptables_monitor_running = 0;
    pthread_join(g_iptables_monitor_thread, NULL);
    g_iptables_monitor_thread = 0;
}

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