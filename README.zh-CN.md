# Agent Shield Auditor (`agent-shield-auditor`) — 中文说明

一款面向 AI Agent、MCP 工具链与自动化工作流的**安全合规审计与虚拟防护盾（Virtual Shield）生成技能包**，遵循开放的 Agent Skills (`SKILL.md`) 规范，可在本地零依赖运行安全扫描，并输出可落地的加固策略与标准审计报告。

---

## 一、主要功能

1. **四大高危攻击面盘点**
   * **提示词与间接注入**：检测外部网页、邮件、表格或上传文件内容未经边界隔离直接拼接进指令的风险。
   * **工具过度授权**：识别通配符命令执行（如 `Bash(*)`）、无限制文件写入或缺少域名白名单的外网请求。
   * **敏感凭证与隐私泄露**：排查配置文件、提示词或日志中暴露的 API Key、私钥、环境变量或客户敏感信息。
   * **未经审批的运行时策略变更**：发现智能体在缺少人工审批或来源校验下尝试修改防火墙、内核/eBPF 或生产策略的风险。

2. **本地零依赖自动化扫描器（`scripts/audit_scanner.py`）**
   * 纯 Python 3.9+ 标准库实现，无需安装第三方依赖，可扫描单个文件或整个目录（支持 `.md`、`.json`、`.yaml`、`.yml`、`.py`、`.sh`、`.txt`、`.env`）。
   * 内置 `SHIELD-001` 至 `SHIELD-005` 五类检测规则，输出结构化 JSON 结果与严重程度统计（`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`）；当检出 `CRITICAL` 级风险时自动返回退出码 `2`，方便接入自动化检查流程。

3. **虚拟防护盾（Virtual Shield）与加固方案生成（`references/shield-patterns.md`）**
   * 提供可直接套用的 **MCP / 工具最小权限白名单 JSON 模板**。
   * 提供 **外部不可信输入 XML 隔离包装模板**，降低间接注入成功率。
   * 提供 **虚拟防护盾上线三步校验清单**（来源签名核验、正常流量审计模式演练、72 小时自动过期 TTL 机制），防止过度拦截影响正常业务。

4. **标准化交付报告模板（`assets/audit-report-template.md`）**
   * 提供结构清晰的安全审计报告模板，涵盖风险概览、漏洞明细表、虚拟防护盾配置与上线签字门禁，可直接用于团队自查或对外交付。

---

## 二、目录结构

```text
agent-shield-auditor/
├── SKILL.md                          # 核心 Agent 技能指令文件
├── README.md                         # 英文主说明文档
├── README.zh-CN.md                   # 中文详细说明文档
├── LICENSE                           # MIT 开源协议
├── scripts/
│   └── audit_scanner.py              # 本地零依赖 Python 安全扫描脚本
├── references/
│   └── shield-patterns.md            # 防护模式、白名单与隔离边界参考库
└── assets/
    ├── audit-report-template.md      # 标准安全审计报告模板
    └── sample_vulnerable_agent.json  # 预置高危 Agent 配置测试样例
```

---

## 三、使用方法

### 方式 A：在终端直接运行扫描脚本（30 秒快速验证）

1. 解压压缩包并进入 `agent-shield-auditor` 目录：
   ```bash
   unzip agent-shield-auditor-v1.0.0.zip
   cd agent-shield-auditor
   ```
2. 运行内置高危测试样例进行扫描：
   ```bash
   python scripts/audit_scanner.py --target assets/sample_vulnerable_agent.json
   ```
3. 扫描你自己的 Agent 配置、提示词或项目目录：
   ```bash
   python scripts/audit_scanner.py --target /path/to/your/agent-or-skill
   ```

### 方式 B：作为 Skill 接入智能体工作流

1. 将整个 `agent-shield-auditor` 文件夹复制到你的 Agent 技能目录（例如 `~/.claude/skills/`、项目 `.skills/` 或支持 `SKILL.md` 的技能平台）。
2. 在对话中直接调用，例如：
   > “请使用 `agent-shield-auditor` 审计我的 MCP 工具配置，列出高危权限问题，并给出最小权限白名单与人工审批卡点。”

### 方式 C：对照模板输出审计与加固方案

1. 结合扫描输出的 JSON 风险项，查阅 `references/shield-patterns.md` 选择对应的白名单、XML 隔离标签或临时防护规则。
2. 复制 `assets/audit-report-template.md` 填入扫描结果与上线核对项，完成发布前安全签收。

---

## 四、使用注意事项

* **避免规则过宽导致误杀**：封禁策略应尽量配合明确白名单使用，切勿盲目扩大拦截范围导致正常业务中断。
* **上线前先做无害流量演练**：启用临时防护规则前，建议先在只读/审计模式下回放常规请求，确认无误伤后再切入拦截模式，并设置合理过期时间。
