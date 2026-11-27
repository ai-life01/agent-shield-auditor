# Agent Shield Auditor (`agent-shield-auditor`)

> 面向 AI Agent、MCP 配置与 Skill 文件的轻量级、零依赖启发式静态安全扫描工具与加固指南。

**语言 / Language：** [🇺🇸 English](README.md) | [🇨🇳 简体中文](README.zh-CN.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-green.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/Version-1.1.1-orange.svg)](CHANGELOG.md)
[![CI](https://github.com/ai-life01/agent-shield-auditor/actions/workflows/test.yml/badge.svg)](https://github.com/ai-life01/agent-shield-auditor/actions/workflows/test.yml)
[![YouTube Demo](https://img.shields.io/badge/Demo-YouTube-red.svg)](https://youtu.be/1bB5ixiZ0fA)

`agent-shield-auditor` 仅使用 Python 3.9+ 标准库即可在本地运行，无需安装任何第三方依赖。它用于标记需要人工复核的可疑风险模式——**不能**证明漏洞一定可利用，也**不提供**主动运行时拦截防护。

📺 **实操演示视频**：[点击观看 YouTube 完整录屏演示](https://youtu.be/1bB5ixiZ0fA) ｜ [查看 X (Twitter) 同步动态](https://x.com/lilisa2099/status/2126021966759153738)

---

## 一、主要功能

1. **四大高危攻击面盘点**
   * **提示词与间接注入（`SHIELD-003`）**：对常见指令覆盖语句及未转义的用户输入模板标记（`{{user_input}}`）进行提示，供人工复核。
   * **工具过度授权（`SHIELD-001`）**：识别宽泛 Shell 执行模式（如 `Bash(*)`、`shell=True`、`os.system()`）；规则聚焦于高置信度风险特征。
   * **敏感凭证与隐私泄露（`SHIELD-002`）**：匹配常见 API Token 与私钥标记，输出证据片段时会自动对疑似密钥进行脱敏（`[REDACTED_SECRET]`）。
   * **异常外连与运行时策略变更（`SHIELD-004`、`SHIELD-005`）**：检测高风险网络外发、关闭 TLS 证书校验，以及高权限系统/防火墙命令（`sudo`、`iptables`、`ufw`、`ebpf`、`chmod 777`）。

2. **本地零依赖自动化扫描器（`scripts/audit_scanner.py`）**
   * 纯 Python 3.9+ 标准库实现，可直接运行脚本，不必执行 `pip install`。如需把 `agent-shield-auditor` 安装为命令行工具，可选用 `pip` 或 `pipx`（见下方可选安装方式）。
   * 支持扫描单个文件或整个目录中的受支持文件（`.md`、`.json`、`.yaml`、`.yml`、`.py`、`.sh`、`.txt`、`.env`、`.toml`、`.ini`），默认自动跳过常见依赖/构建目录、符号链接及大于 1 MiB 的文件。
   * 同时支持 **结构化 JSON 输出（`--format json`）** 与 **一键生成可读 Markdown 审查报告（`--format md --output audit-report.md`）**，方便人工阅读与交付归档。
   * 标准 CLI 退出码：
     * `0`：扫描完成且未发现 `CRITICAL` 级别模式或读取错误
     * `1`：目标路径不存在或读取文件出错
     * `2`：发现至少一条 `CRITICAL` 级别可疑模式

3. **虚拟防护盾（Virtual Shield）与加固方案参考（`references/shield-patterns.md`）**
   * 提供可直接套用的 **MCP / 工具最小权限白名单 JSON 模板**。
   * 提供 **外部不可信输入 XML 隔离包装模板**，降低间接提示词注入风险。
   * 提供 **虚拟防护盾上线三步校验清单**（来源校验、正常流量审计模式演练、72 小时自动过期 TTL 机制），避免误杀正常业务。

4. **标准化交付报告模板（`assets/audit-report-template.md`）**
   * 提供结构清晰的安全审计报告模板，涵盖风险概览、漏洞明细表、防护配置建议与上线签字门禁（使用 `--format md` 时也会自动按此结构填充生成）。

---

## 二、目录结构

```text
agent-shield-auditor/
├── .github/
│   └── workflows/
│       └── test.yml                  # GitHub Actions 自动化单元测试配置
├── .gitignore                        # Python / 打包相关忽略规则
├── pyproject.toml                    # 可选的 pip/pipx 安装配置
├── SKILL.md                          # 核心 Agent 技能指令文件
├── README.md                         # 英文主说明文档
├── README.zh-CN.md                   # 中文详细说明文档
├── CHANGELOG.md                      # 版本更新日志
├── LICENSE                           # MIT 开源协议
├── scripts/
│   ├── __init__.py
│   └── audit_scanner.py              # 本地零依赖 Python 安全扫描脚本
├── references/
│   └── shield-patterns.md            # 防护模式、白名单与隔离边界参考库
├── assets/
│   ├── audit-report-template.md      # 标准安全审计报告模板
│   └── sample_vulnerable_agent.json  # 预置高危 Agent 配置测试样例
└── tests/
    ├── __init__.py
    └── test_audit_scanner.py         # 标准库单元测试套件
```

---

## 三、使用方法

### 方式 A：在终端直接运行扫描脚本（30 秒快速验证）

1. 克隆仓库或解压发布包并进入项目目录：
   ```bash
   git clone https://github.com/ai-life01/agent-shield-auditor.git
   cd agent-shield-auditor
   ```
   *（若使用发布压缩包：`unzip agent-shield-auditor-v1.1.0-v4.zip && cd agent-shield-auditor`）*
2. 运行内置高危测试样例进行扫描（默认输出 JSON）：
   ```bash
   python scripts/audit_scanner.py --target assets/sample_vulnerable_agent.json
   ```
3. 一键生成可直接阅读或交付的 Markdown 安全审查报告（`--format md`）：
   ```bash
   python scripts/audit_scanner.py --target assets/sample_vulnerable_agent.json --format md --output audit-report.md
   ```
4. 扫描你自己的 Agent 配置、提示词或项目目录并导出报告：
   ```bash
   python scripts/audit_scanner.py --target /path/to/your/agent-or-skill --format md --output my-audit-report.md
   ```

#### JSON 输出示例

```json
{
  "target": "assets/sample_vulnerable_agent.json",
  "files_scanned": 1,
  "files_skipped": 0,
  "total_findings": 4,
  "severity_summary": {
    "CRITICAL": 2,
    "HIGH": 1,
    "MEDIUM": 1,
    "LOW": 0
  }
}
```

### 方式 B：使用 pip 或 pipx 安装（可选）

扫描器运行时没有任何第三方依赖。只有在希望把 `agent-shield-auditor` 安装到系统命令行时，才需要执行下面的安装步骤：

```bash
pip install git+https://github.com/ai-life01/agent-shield-auditor.git
# 或者使用独立环境，避免影响系统 Python：
pipx install git+https://github.com/ai-life01/agent-shield-auditor.git
```

安装后可以直接扫描文件或目录：

```bash
agent-shield-auditor --target /path/to/your/agent-or-skill
agent-shield-auditor --target assets/sample_vulnerable_agent.json --format md --output audit-report.md
```

你仍然可以在克隆下来的仓库里直接运行 `python scripts/audit_scanner.py --target ...`，无需安装。

### 方式 C：作为 Skill 接入智能体工作流

1. 将整个 `agent-shield-auditor` 文件夹复制到你的 Agent 技能目录（例如 `~/.claude/skills/`、项目 `.skills/` 或支持 `SKILL.md` 的技能平台）。
2. 在对话中直接调用，例如：
   > “请使用 `agent-shield-auditor` 审计我的 MCP 工具配置，列出高危权限问题，并给出最小权限白名单与人工审批卡点。”

### 方式 D：复核生成的 Markdown 报告并完成加固

1. 打开自动生成的 `.md` 审查报告（或对照 `assets/audit-report-template.md`），查阅 `references/shield-patterns.md` 选择对应的白名单、XML 隔离标签或临时防护规则。
2. 逐项确认报告末尾的上线核对清单，完成发布前安全签收。

---

## 四、排除文件与运行测试

如果目标目录中包含文档、测试样例等不应扫描的文件，可以重复使用 `--exclude` 参数：

```bash
python scripts/audit_scanner.py --target ./my-agent --exclude "README.md" --exclude "tests/*"
```

> **提示：** 若目标目录包含文档或测试夹具，建议通过 `--exclude` 排除以避免将示例误报为风险。请勿将本扫描器自身的源码仓库当作真实 Agent 项目进行代表性测试。

运行自带单元测试套件：

```bash
python -m unittest discover -v
```

---

## 五、使用注意事项与局限性

* **避免规则过宽导致误杀**：封禁策略应尽量配合明确白名单使用，切勿盲目扩大拦截范围导致正常业务中断。
* **扫描器不会主动拦截流量**：参考资料中的防护模式是指导模板，不是已运行的运行时防护盾。
* **每条发现都需要人工复核**：静态匹配可能误报，也可能漏报；没有发现不代表系统绝对安全。
* **实施防护前先演练**：任何单独实现的临时拦截规则，都应先在正常流量上验证后再启用阻断。

---

## 六、联系与反馈

* **问题反馈与规则建议**：前往 [GitHub Issues](https://github.com/ai-life01/agent-shield-auditor/issues) 提交
* **实操演示视频**：[观看 YouTube 演示视频](https://youtu.be/1bB5ixiZ0fA)
* **日常交流 / 初步筛查协助**：在 [X (@lilisa2099)](https://x.com/lilisa2099) 留言或私信（[演示推文](https://x.com/lilisa2099/status/2126021966759153738)）
* **联系邮箱**：`aikanhai677@gmail.com`
* **支持作者**：如果这个项目对你有帮助，欢迎在 [爱发电](https://ifdian.net/a/yuanqiailab) 支持一下。
