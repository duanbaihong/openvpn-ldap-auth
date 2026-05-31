# openvpn-ldap-auth AGENTS.md

**Generated:** 2026-05-31
**Commit:** aa3feed
**Branch:** master

## OVERVIEW

OpenVPN LDAP 认证插件（基于 chantra/openvpn-ldap-auth 修改），C/autotools 项目，支持组成员认证、iptables 策略映射、YAML 配置。

## STRUCTURE

```
./
├── src/             # 插件源码全部在此（23 .c/.h），无子目录
├── tests/           # 手动集成测试 + LDAP 搜索工具
├── configure.in     # 旧版 Autoconf 命名（应为 configure.ac）
├── .vscode/         # IDE 配置，C11/clang
└── autogen.sh       # 从 HPLIP 复制的模板脚本
```

## WHERE TO LOOK

| 任务 | 位置 | 备注 |
|------|------|------|
| 插件入口 | `src/ldap-auth.c` | openvpn_plugin_open_v2 / func_v2 / close_v1 等 7 个导出函数 |
| LDAP 认证逻辑 | `src/la_ldap.c` | 804 行，项目最大文件 |
| YAML 配置解析 | `src/cnf.c` | 使用 libyaml，配置结构定义在 cnf.h |
| iptables 规则 | `src/la_iptables.c` | 角色策略管理 |
| 动作队列/线程 | `src/action.c` + `src/queue.c` | 异步认证线程 |
| 客户端上下文 | `src/client_context.c` | 每连接上下文 |
| 调试日志 | `src/debug.h` | LOGERROR/LOGINFO/LOGDEBUG 等宏 |
| 自定义内存分配 | `src/utils.c` | la_malloc/la_free 封装 |
| 测试驱动 | `tests/openvpn-ldap-auth-test.c` | 手动交互式集成测试 |
| 构建配置 | `configure.in` + `src/Makefile.am` | Autotools |
| LDAP Schema | `tests/ovpn.schema` | OpenVPN 自定义 schema |

## CONVENTIONS

### 编码风格（来自 vim modeline）
- 缩进: **2 空格，expandtab**
- 编译器: `-Wall -Werror`

### 命名约定
- 类型: `snake_case_t`（如 `ldap_context_t`）
- 函数: `snake_case`，库函数前缀 `la_`
- 宏: `UPPER_CASE`
- new/free 模式: `type_new()` / `type_free()`
- 头文件保护: `_NAME_H_` 或 `__NAME_H__`（不一致，均非标准）

### 构建
- GNU Autotools（autoconf + automake + libtool）
- 产物: `libopenvpn-ldap-auth.la`（共享库）
- CFLAGS 硬编码 `-Werror`（构建可能因编译器版本差异失败）
- 依赖: libldap, liblber, libyaml, pthread

### 许可证
- 核心文件: GPL v2
- 部分库文件: LGPL v2.1

## ANTI-PATTERNS（THIS PROJECT）

- **strdup/malloc 返回值未检查**: 全项目 66+ 处，OOM 时 NULL 解引用
- **注释掉的 free()**: `src/la_ldap.c` 中 3 处确认泄漏（608/622 行 LDAP 属性/消息泄漏，508/515 行连接泄漏）
- **全局变量定义在头文件**: `cnf.h`（iptblrules/ldapconfig/openvpnserverinfo）、`action.h`（mutex/cond）、`queue.h`（ConnVpnQueue_r）——非 extern 声明，可能导致多重定义
- **realloc 指针丢失**: `src/utils.c:231`、`src/cnf.c:235/247`，失败时原指针泄漏
- **TLS 证书未验证**: `src/la_ldap.c:464` 调用 `ldap_start_tls_s` 传 NULL，`TLS_REQCERT` 默认 NEVER
- **双重 AM_INIT_AUTOMAKE**: `configure.in` 第 8/13 行
- **混合 // 和 /* */ 注释**: `queue.h`、`la_iptables.h` 用 `//`，其余用 `/* */`
- **中英文注释混杂**: `queue.h` 中文注释，其余英文
- **驼峰命名代码**: `queue.h`（VpnData, InitConnVpnQueue）偏离全局 snake_case

## NOTES

- 无 CI/CD（无 GitHub Actions）、无单元测试框架、无 .clang-format/.editorconfig
- 无 `make check` 目标，测试需手动运行
- `autogen.sh` 包含 Debian 打包逻辑（来自 HPLIP 模板）
- 项目使用 `foreign` automake 模式（不强制 NEWS/AUTHORS 等 GNU 标准文件）