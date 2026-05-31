# 动态加载 iptables 策略设计方案

## 概述

当前 iptables 策略在 OpenVPN 插件启动时从 OpenLDAP 加载一次，策略变更后需要重启 OpenVPN 才能生效。
本方案实现**动态加载**：LDAP 上的 iptables 策略变更后，自动检测并热更新，无需重启。

## 现状

启动时加载流程：

```
openvpn_plugin_open_v2()
  → config_init_ldap_config_set()
    → config_load_ldap_groups_profiles(l)     // 查询 LDAP 所有组
    → config_iptable_role_merge()              // 合并 YAML 规则
    → config_init_iptable_rules()              // 创建 iptables 链
用户上线 → la_learn_roles_add()                // -I FORWARD -s IP -j CHAIN
用户下线 → la_learn_roles_delete()              // -D FORWARD -s IP -j CHAIN
插件卸载 → config_uninit_iptable_rules()        // 清空并删除链
```

**关键数据流：**

```
LDAP (groupMapField/iptableRulesField)
  → config_load_ldap_groups_profiles()
    → LdapIptableRoles { clen, chains[{chain_name, rule_len, rule_item[]}] }
      → profile_config_t->iptable_rules
        → config_init_iptable_rules()  → iptables -N/-A
```

## 设计

### 整体架构

```
┌──────────────────────────────────────────────────────────────┐
│                        轮询线程                              │
│  每 60 秒:                                                    │
│    1. 连接 LDAP，重新查询所有组规则                           │
│    2. 构建新 LdapIptableRoles                                 │
│    3. 合并 YAML 配置中的 iptblrules                           │
│    4. 比较新旧规则（链数量 + 链名称 + 规则数量）              │
│    5. 有变更 → 锁定 mutex → 全量热更新 → 解锁                 │
│       无变更 → 释放新规则，继续等待                           │
└──────────────────────────────────────────────────────────────┘
```

### 新增文件/函数

**`la_iptables.c` 新增 3 个函数：**

```c
// 比较新旧规则是否一致
// 返回 0=相同, 1=不同
static int iptables_rules_changed(LdapIptableRoles *old, LdapIptableRoles *new);

// 重新加载 LDAP 策略并热更新
// 由轮询线程或管理命令触发
int la_iptables_reload(ldap_context_t *l);

// 轮询线程入口
static void *iptables_monitor_thread(void *arg);
```

**`la_iptables.h` 新增声明：**

```c
extern int la_iptables_reload(ldap_context_t *l);
extern int la_iptables_start_monitor(ldap_context_t *l);
extern void la_iptables_stop_monitor(void);
```

**`action.h` 新增变量：**

```c
extern pthread_t g_iptables_monitor_thread;  // 轮询线程 ID
extern volatile int g_iptables_monitor_running;  // 线程运行标志
```

**`ldap-auth.c` 修改 2 处：**

```c
openvpn_plugin_open_v2() → 末尾: la_iptables_start_monitor(context);
openvpn_plugin_close_v1() → 开头: la_iptables_stop_monitor();
```

### 规则比较逻辑（rules_changed）

```c
static int iptables_rules_changed(LdapIptableRoles *old, LdapIptableRoles *new) {
    if (old->clen != new->clen) return 1;
    for (int i = 0; i < old->clen; i++) {
        // 比较 chain_name
        if (strcmp(old->chains[i].chain_name, new->chains[i].chain_name) != 0)
            return 1;
        // 比较 rule_len（如果规则数量变了说明内容变了）
        if (old->chains[i].rule_len != new->chains[i].rule_len)
            return 1;
        // 快速比较：不逐条比较 rule_item 内容，变更规则通常伴随数量变化
    }
    return 0;
}
```

### 热更新流程（reload）

```c
int la_iptables_reload(ldap_context_t *l) {
    // 获取当前 profile（项目中只使用第一个 profile）
    profile_config_t *lp = l->config->profiles->first->data;
    LdapIptableRoles *old_rules = lp->iptable_rules;
    
    // 1. 重新查询 LDAP 构建新规则
    // 策略：保存旧规则 → 调用 config_load_ldap_groups_profiles() → 新规则写入
    //        lp->iptable_rules → 从 lp 取出与旧规则比较 → 决定是否替换
    LdapIptableRoles *old_rules_saved = lp->iptable_rules;
    int ret = config_load_ldap_groups_profiles(l);
    LdapIptableRoles *new_rules = lp->iptable_rules;
    if (ret != 0 || !new_rules) {
        lp->iptable_rules = old_rules_saved;  // 恢复旧规则
        return -1;
    }
    lp->iptable_rules = old_rules_saved;  // 先恢复，等变更判断后再决定换不换
    
    // 2. 合并 YAML 配置的规则
    config_iptable_role_merge(new_rules, iptblrules);
    
    // 3. 比较变更
    if (!iptables_rules_changed(old_rules, new_rules)) {
        ldap_iptables_roles_free(new_rules);
        LOGDEBUG("iptables rules unchanged, skip reload");
        return 0;
    }
    
    // 4. 热更新（持有 action_mutex 锁）
    pthread_mutex_lock(&action_mutex);
    
    // 4a. 删除旧链
    config_uninit_iptable_rules(old_rules);
    
    // 4b. 切换为新规则
    lp->iptable_rules = new_rules;
    
    // 4c. 创建新链
    config_init_iptable_rules(new_rules);
    
    // 4d. 重新添加所有在线用户的 FORWARD 规则
    // 遍历 ConnVpnQueue_r（需外部传入或全局访问）
    for (ConnNode *n = ConnVpnQueue_r->front->next; n != NULL; n = n->next) {
        la_learn_roles_add(n->data);
    }
    
    // 4e. 释放旧规则
    ldap_iptables_roles_free(old_rules);
    
    pthread_mutex_unlock(&action_mutex);
    
    LOGINFO("iptables rules reloaded successfully: %d chains", new_rules->clen);
    return 0;
}
```

### 轮询线程入口

```c
static void *iptables_monitor_thread(void *arg) {
    ldap_context_t *l = (ldap_context_t *)arg;
    g_iptables_monitor_running = 1;
    
    while (g_iptables_monitor_running) {
        sleep(60);  // 轮询间隔 60 秒
        if (!g_iptables_monitor_running) break;
        la_iptables_reload(l);
    }
    return NULL;
}
```

### 线程安全

| 线程 | 访问资源 | 保护机制 |
|------|---------|---------|
| 轮询线程 | `lp->iptable_rules`、`ConnVpnQueue_r` | `action_mutex` |
| LEARN_ADDRESS 回调 | `la_learn_roles_add/delete` | 热更新期间等待锁释放 |
| 认证线程 | `config_load_ldap_groups_profiles` | 独立调用，不共享状态 |

## 变更文件清单

| 文件 | 操作 | 行数变化 |
|------|------|---------|
| `src/la_iptables.h` | 新增 3 个函数声明 | +6 |
| `src/la_iptables.c` | 新增 3 个函数实现 | +100 |
| `src/action.h` | 新增 2 个全局变量 | +3 |
| `src/ldap-auth.c` | 启动/停止监测线程 | +15 |
| 总计 | | ~124 行新增 |

## 注意事项

1. **轮询间隔**：当前固定 60 秒。如需修改，可改为 YAML 配置项
2. **错误处理**：LDAP 连接失败时跳过本轮轮询，等待下一轮
3. **日志**：变更和不变更都有 LOGINFO/LOGDEBUG 日志
4. **停用**：通过 `g_iptables_monitor_running = 0` + `pthread_cancel` 安全停止
