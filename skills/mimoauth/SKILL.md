---
name: mimoauth
description: 通过 mimoauthctl 与 MiMoAuth 鉴权服务交互 —— 发起提权授权请求、查询/撤销授权缓存、查看策略规则。当 Agent 需要执行需要提权的系统操作（sudo、pkexec、系统设置、软件包管理），或用户提到「授权弹窗 / 认证 / MiMoAuth / mimoauthctl」时使用。
---

# MiMoAuth Agent 技能

MiMoAuth 是本机的 polkit 风格鉴权框架（系统服务 + GUI/TUI 认证代理 + Agent 工具链）。
Agent 通过 `mimoauthctl`（D-Bus 连接 `mimoauthd`）完成授权流程。
**Agent 永远不接触、不输入用户密码** —— 密码/指纹只由用户在认证界面完成。

## 前置检查

```bash
$HOME/.local/bin/mimoauthctl ping    # 退出码 0 = 运行中；3 = 未运行
```

未运行时提示用户 `systemctl --user start mimoauthd`（或 `scripts/install.sh`），然后停止，不要反复重试。

> 所有命令一律使用绝对路径 `$HOME/.local/bin/mimoauthctl`（Agent 的 PATH 通常不含 `~/.local/bin`）。

## 核心命令

所有命令都支持 `--json`（机器可读），Agent 必须加 `--json`。

### 1. 先查询，避免重复弹窗

```bash
$HOME/.local/bin/mimoauthctl status --json            # 本用户全部缓存授权
$HOME/.local/bin/mimoauthctl status org.example.action --json
```

输出示例：`{"action_id":"...","authorized":true,"remaining_ms":183422}`。
`status` 永远不触发弹窗。

### 2. 发起授权（会弹认证窗口）

```bash
$HOME/.local/bin/mimoauthctl request org.example.packagekit.install \
  --description "安装软件包 foo" \
  --command "apt-get install foo" \
  --source mimo \
  --timeout-ms 60000 --json
```

- `action`：稳定动作 ID，建议 `<reverse-dns>.<动作>`，与规则文件模式对应。
- `--description`：给用户的**人话**说明（谁、要做什么），必填级重要。
- `--command`：本次授权**将要执行的命令**（如 `sudo rm /opt/x`），原样显示在弹窗「命令」行；不传则回退显示调用方进程命令行。
- `--source`：`mimo`（MiMo Desktop）/ `ai`（其他 Agent）/ `user`（用户终端）。**MiMo Desktop 的 Agent 一律传 `--source mimo`**——弹窗标题与图标按来源区分。
- `--timeout-ms`：总等待预算；0 = daemon 默认（60s）。建议 30000–60000。

输出：`{"action_id":"...","outcome":"allow|deny|timeout|error","reason":"..."}`

| 退出码 | outcome | Agent 行为 |
|---|---|---|
| 0 | allow | 继续执行提权操作 |
| 1 | deny | **不要重试**，向用户报告被拒绝 |
| 2 | timeout | 用户未响应；告知后改天/改方式，不要立刻重发 |
| 3 | error | 检查 reason（`no-agent` = 认证界面不可用，`agent-exit` = 界面崩溃） |

### 3. 撤销授权缓存

```bash
$HOME/.local/bin/mimoauthctl revoke --json                 # 撤销本用户全部
$HOME/.local/bin/mimoauthctl revoke org.example.action --json
```

### 4. 查看生效策略

```bash
$HOME/.local/bin/mimoauthctl rules --json
```

首行 `pattern:"*"` 为默认效果；规则文件：`~/.config/mimoauth/rules.toml`（后条覆盖前条）。

## 弹窗行为（供向用户解释）

- 有指纹设备时**默认进入指纹模式**（不显示密码框），未识别超时后自动切回密码输入（默认 10 秒，`config.toml` 的 `fingerprint_timeout_secs` 可调）；无指纹设备则只有密码框。
- 来源区分：MiMo / 其他 AI Agent / 用户终端三类弹窗的标题、副标题、图标不同。
- `auth_admin_keep` 认证成功后短时缓存（默认 300s），期间同动作直接放行。
- **锁屏会清空全部授权缓存**（≤5 秒内生效）。
- 无图形环境（SSH）时 `request` 自动切换为终端行内认证。

## 效果语义

- `allow`：直接成功不弹窗。
- `auth_admin`：每次都弹窗，不缓存。
- `auth_admin_keep`：认证一次后缓存（keep_timeout），期间免密。
- `deny`：直接拒绝（reason=`policy-deny`）。

## 工作流规范

1. **先 `status` 后 `request`**：缓存期内免弹窗。
2. **一次只等一个请求**：`request` 阻塞，不要并发。
3. **永不传密码**：CLI 无任何密码参数；`auth-failed` 只上报，不重试输密码。
4. **timeout ≠ deny**：措辞上区分「用户没理」与「用户拒绝」。
5. **失败不绕过**：deny/timeout/error 时不要改用 `sudo -n` 之类硬闯，如实告知用户。
6. **如实描述**：`--description`/`--command` 必须真实反映将执行的操作，禁止虚构用途（弹窗展示给用户直接查看）。

## sudo 场景说明

已安装 PAM 集成（`/etc/pam.d/sudo` 中的 `pam_exec … pam-hook`）后，用户在**真实终端**执行 `sudo <cmd>` 会自动弹出「正在请求系统权限」弹窗（命令行显示该 sudo 命令），指纹通过即免密执行；取消/超时自动回落传统密码输入。此路径无需 Agent 参与。
