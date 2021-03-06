// #include "queue.h"
// #include "client_context.h"

typedef enum
{
  IPTABLE_CREATE_FILTER = 1,
  IPTABLE_EMPTY_FILTER,
  IPTABLE_DELETE_FILTER,
  IPTABLE_APPEND_ROLE,
  IPTABLE_INSERT_ROLE,
  IPTABLE_INSERT_MASQUERADE_ROLE,
  IPTABLE_DELETE_ROLE,
  IPTABLE_DELETE_MASQUERADE_ROLE
} iptable_rules_action_type;

extern const char *IPT_RULES_FMT;
extern int la_learn_roles_add(VpnData *vdata);
extern int la_learn_roles_delete(VpnData *vdata);
extern void config_iptables_printf(LdapIptableRoles *rules);
extern void config_init_iptable_rules(LdapIptableRoles *rules);
extern void config_uninit_iptable_rules(LdapIptableRoles *rules);
extern int ldap_plugin_run_system(iptable_rules_action_type cmd_type,char * filter_name, char * rule_item);