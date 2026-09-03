# Archery SQL Skills

面向 Archery v1.8.0 的四个 SQL Agent Skill，适用于 Claude Code 和 Codex：

| Skill | 用途 | 写操作 |
| --- | --- | --- |
| `archery-query-sql` | 执行 `SELECT` 或 `EXPLAIN SELECT` | 否 |
| `archery-submit-sql` | 检查 SQL 并创建审批工单 | 仅创建工单 |
| `archery-review-sql` | 查看、通过或驳回待审批工单 | 审批状态变更 |
| `archery-execute-sql` | 执行已最终审批的 `UPDATE` 或 `INSERT` 工单 | 是 |

仓库不包含真实的 Archery 地址、实例名称、数据库名称、账号密码或执行口令。部署信息保存在仓库外的共享配置文件中，凭证保存在环境变量中。

## 环境要求

- Python 3.8 或更高版本
- 可访问 Archery v1.8.0 服务
- 与操作相匹配的 Archery 查询、提交、审批或执行权限
- Claude Code 或 Codex

## 安装

安装到 Claude Code：

```bash
./scripts/install.sh claude
```

安装到 Codex：

```bash
./scripts/install.sh codex
```

同时安装：

```bash
./scripts/install.sh all
```

脚本会更新同名 Skill 中的文件，但不会删除目标目录里的额外文件。重启 Agent 运行时，使其重新发现 Skill。

## 配置

创建仓库外配置并限制文件权限：

```bash
mkdir -p "$HOME/.config/archery-sql-skills"
cp config.example.json "$HOME/.config/archery-sql-skills/config.json"
chmod 600 "$HOME/.config/archery-sql-skills/config.json"
```

编辑该文件：

- `base_url`：Archery 服务地址
- `query.instances`：允许查询的实例白名单
- `submit.instances`：允许提交工单的可写实例白名单
- `default_database`：可省略；省略后每次必须明确指定数据库
- `aliases`：可选的查询实例别名

实例 ID 与名称必须同时匹配 Archery 当前返回值。不要把真实配置复制回仓库。

四个 Skill 默认读取 `~/.config/archery-sql-skills/config.json`。也可以设置 `ARCHERY_CONFIG_FILE` 指向其他绝对路径，或在直接运行客户端时传入全局参数 `--config <path>`。

## 凭证

| 变量 | 用途 |
| --- | --- |
| `ARCHERY_USERNAME` | 查询与工单提交账号 |
| `ARCHERY_PASSWORD` | 查询与工单提交密码 |
| `ARCHERY_REVIEW_USERNAME` | 审批专用账号 |
| `ARCHERY_REVIEW_PASSWORD` | 审批专用密码 |
| `ARCHERY_EXECUTE_USERNAME` | 执行专用账号 |
| `ARCHERY_EXECUTE_PASSWORD` | 执行专用密码 |
| `ARCHERY_EXECUTE_CONFIRM_TOKEN` | 执行阶段的二次口令 |

macOS 可使用隐藏输入脚本，将变量设置到当前登录会话：

```bash
./scripts/configure-macos.sh
```

该脚本不会显示或写入凭证。`launchctl setenv` 通常不会跨登录会话永久保存，重新登录后需要再次配置，或由企业密钥管理方案注入。Linux/CI 环境应通过 shell、CI Secret 或密钥管理服务设置同名变量。

## 使用方式

在 Claude Code 或 Codex 中直接描述目标并点名 Skill，例如：

```text
使用 /archery-query-sql，在 test 实例的 app_db 执行：SELECT 1
```

```text
使用 /archery-submit-sql，检查这条 SQL 并提交审批工单：UPDATE users SET status = 1 WHERE id = 10
```

```text
使用 /archery-review-sql，查看工单 42，确认后以“检查通过”为备注审批通过
```

```text
使用 /archery-execute-sql，检查并执行已最终审批的工单 42
```

Agent 必须按 Skill 中的检查、预览和二次确认流程执行。配置里的示例实例和数据库名称只是占位符。

## 安全边界

- 查询只接受一条 `SELECT` 或 `EXPLAIN SELECT`，默认最多 100 行，配置上限最多 1000 行。
- 提交前执行 Archery 服务端检查；错误阻止提交，警告必须明确接受，检查后必须再次确认。
- 审批前重新读取完整工单并校验指纹；一次只通过或驳回一个工单。
- 执行只接受已最终审批工单中的 `UPDATE` 或 `INSERT`，始终拒绝 `DELETE`。
- `UPDATE` 必须在顶层 `WHERE` 中具有明确的字面量 `id = ...` 或 `id IN (...)` 条件。
- `INSERT` 必须显式列出字段并使用 `VALUES`，不要求包含 `id` 字段。
- 服务端预计影响行数必须严格小于 50；执行前需要新指纹、用户确认和环境口令。
- 审批和执行请求发生超时、断连或 HTTP 5xx 时不自动重试，应先检查 Archery 状态与日志。

执行口令只能减少误操作。能够读取 Agent 进程环境的代码仍可读取该口令，因此账号最小权限和 Archery 服务端权限控制仍是主要安全边界。

## 测试

```bash
python3 -m unittest -v skills/archery-query-sql/scripts/test_archery_query.py
python3 -m unittest -v skills/archery-submit-sql/scripts/test_archery_client.py
python3 -m unittest -v skills/archery-review-sql/scripts/test_archery_review.py
python3 -m unittest -v skills/archery-execute-sql/scripts/test_archery_execute.py
```

这些测试使用本地模拟服务，不会连接真实 Archery，也不会提交、审批或执行真实 SQL。
