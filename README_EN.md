# HTTPS SSL Manager

SSL certificate automation using ACME (Let's Encrypt) + Alibaba Cloud DNS. Designed as an Agent Skill.

## As Agent Skill

Link the skill package to your project's skills directory:

```bash
# Windows (PowerShell Junction)
New-Item -ItemType Junction -Path ".claude\skills\get-ssl-skill" -Target "\path\to\get-ssl-ali\get-ssl-ali"

# Linux (symlink)
ln -s /path/to/get-ssl-ali/get-ssl-ali .claude/skills/get-ssl-skill
```

Then use in agent:

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

# Or use natural language
Apply certificate for example.com
```

| Command | Description |
|---------|-------------|
| `check` | Check ACME status and certificate expiry |
| `apply` | Issue new certificate (supports wildcard + SAN) |
| `deploy` | Deploy certificate to servers |
| `renew` | Batch renew expiring certificates |
| `list` | List configured domains and servers |
| `diagnose` | Diagnose ACME and API status |
| `setup-persist` | Setup DNS-PERSIST-01 persistent record |

> `apply` / `deploy` / `renew` / `setup-persist` will show dry-run first, execute after confirmation.

## Configuration

Copy the config template:

```bash
cp get-ssl-ali/config/config.example.yaml get-ssl-ali/config/config.yaml
```

Key settings (see `config/config.example.yaml` for details):

```yaml
aliyun:
  access_key_id: "${ALIYUN_ACCESS_KEY_ID}"    # Aliyun AccessKey ID
  access_key_secret: "${ALIYUN_ACCESS_KEY_SECRET}"  # Aliyun AccessKey Secret

acme:
  enabled: true
  email: "${ACME_EMAIL}"                       # Let's Encrypt registration email

domains:
  - domain: "example.com"                      # Domain to issue certificate for
    servers:
      - host: "192.168.1.10"                   # Server IP
        user: "root"                          # SSH username
        password: "${SSH_PASS}"                # SSH password
        cert_path: "/etc/nginx/ssl/example.com.pem"      # Certificate deploy path (fullchain.pem)
        key_path: "/etc/nginx/ssl/example.com.key"        # Private key deploy path (privkey.pem)
        reload_cmd: "nginx -t && systemctl reload nginx"  # Command to run after deploy

# Optional: wildcard + SAN
# - domain: "*.example.com"
#   san: ["example.com"]                      # Also covers bare domain
```

Supports `${ENV_VAR}` syntax. Never put sensitive values directly in the config file.

## Screenshots

### List Configurations
```bash
/get-ssl-skill list
```
![List demonstration](images/list.png)

### Check Status
```bash
/get-ssl-skill check
```
![Check status demonstration](images/check.png)

### Diagnose
```bash
/get-ssl-skill diagnose
```
![Diagnose demonstration](images/diagnose.png)

### Issue Certificate
```bash
/get-ssl-skill apply --domain example.com
```
![Issue certificate demonstration](images/apply.png)
![Confirmation demonstration](images/apply_confirm.png)

### Deploy Certificate
```bash
/get-ssl-skill deploy --domain example.com
```
![Deploy demonstration](images/deploy.png)
![Confirmation demonstration](images/deploy_confirm.png)

### Renew Certificate
```bash
/get-ssl-skill renew
```
![Renew demonstration](images/renew.png)

## Project Structure

```
get-ssl-ali/                      # Project root
├── get-ssl-ali/                  # Skill package (link to .claude/skills/get-ssl-skill)
│   ├── SKILL.md                  # Skill definition
│   ├── config/config.yaml        # Config file
│   ├── certs/                    # Certificate storage
│   └── scripts/ssl_manager/  # Python code
├── README.md
└── LICENSE
```

## License

MIT License - see [LICENSE](LICENSE)
