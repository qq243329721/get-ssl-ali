# 阿里云 SSL 证书管理

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

基于 ACME (Let's Encrypt) + 阿里云 DNS 的 SSL 证书自动化工具，可作为 Claude/OpenCode/OpenClaw Skill 使用。

## 作为 Agent Skill 使用

将 skill 包关联到项目的 skills 目录：

```bash
# Windows（PowerShell Junction）
New-Item -ItemType Junction -Path ".claude\skills\get-ssl-skill" -Target "\path\to\get-ssl-ali\get-ssl-ali"

# Linux（软链接）
ln -s /path/to/get-ssl-ali/get-ssl-ali .claude/skills/get-ssl-skill
```

关联后在 agent 中直接使用：

```
/get-ssl-skill check

/get-ssl-skill list
/get-ssl-skill apply --domain example.com
/get-ssl-skill apply --domain "*.example.com"
/get-ssl-skill deploy --domain example.com
/get-ssl-skill renew
/get-ssl-skill renew --domain example.com
/get-ssl-skill setup-persist --domain "*.example.com"
/get-ssl-skill diagnose

# 或者直接使用自然语言
帮我申请example.com的证书 
```

| 命令 | 说明 |
|------|------|
| `check` | 检查 ACME 状态和证书过期时间 |
| `apply` | 申请新证书（支持泛域名 + SAN） |
| `deploy` | 部署证书到服务器 |
| `renew` | 批量续期即将过期的证书 |
| `list` | 列出已配置的域名和服务器 |
| `diagnose` | 诊断 ACME 和 API 状态 |
| `setup-persist` | 配置 DNS-PERSIST-01 持久化记录 |

> `apply` / `deploy` / `renew` / `setup-persist` 会先执行 dry-run 预览，确认后执行。


## 使用截图

### 列表查看
```bash
/get-ssl-skill list
```
![list 命令演示](images/list.png)

### 检查状态
```bash
/get-ssl-skill check
```
![check 命令演示](images/check.png)

### 诊断
```bash
/get-ssl-skill diagnose
```
![diagnose 命令演示](images/diagnose.png)

### 申请证书
```bash
/get-ssl-skill apply --domain example.com
```
![apply 命令演示](images/apply.png)
![apply 确认演示](images/apply_confirm.png)

### 部署证书
```bash
/get-ssl-skill deploy --domain example.com
```
![deploy 命令演示](images/deploy.png)
![deploy 确认演示](images/deploy_confirm.png)

### 续期证书
```bash
/get-ssl-skill renew
```
![renew 命令演示](images/renew.png)

## 使用方法

### 配置技能
复制配置模板并编辑：

```bash
cp get-ssl-ali/config/config.example.yaml get-ssl-ali/config/config.yaml
```

### 配置相关参数
主要配置项（详细说明见 `config/config.example.yaml`）：

```yaml
aliyun:
  access_key_id: "${ALIYUN_ACCESS_KEY_ID}"    # 阿里云 AccessKey ID
  access_key_secret: "${ALIYUN_ACCESS_KEY_SECRET}"  # 阿里云 AccessKey Secret

acme:
  enabled: true
  email: "${ACME_EMAIL}"                       # Let's Encrypt 注册邮箱

domains:
  - domain: "example.com"                      # 要申请证书的域名
    servers:
      - host: "192.168.1.10"                   # 服务器 IP
        user: "root"                          # SSH 用户名
        password: "${SSH_PASS}"                # SSH 密码
        cert_path: "/etc/nginx/ssl/example.com.pem"      # 证书部署路径（fullchain.pem）
        key_path: "/etc/nginx/ssl/example.com.key"        # 私钥部署路径（privkey.pem）
        reload_cmd: "nginx -t && systemctl reload nginx"  # 部署后执行命令

# 可选：泛域名 + SAN
# - domain: "*.example.com"
#   san: ["example.com"]                      # 同时覆盖根域名
```

支持 `${ENV_VAR}` 语法引用环境变量，敏感信息不要直接写在配置文件中。


## 项目结构

```
get-ssl-ali/                      # 主项目目录
├── get-ssl-ali/                  # Skill 包（链接到 .claude/skills/get-ssl-skill）
│   ├── SKILL.md                  # Skill 定义
│   ├── config/config.yaml        # 配置文件
│   ├── certs/                    # 证书存储
│   └── scripts/ssl_manager/  # Python 代码
├── README.md
└── LICENSE
```

## 许可证

MIT License - 详见 [LICENSE](LICENSE)
