"""Config loading with environment variable substitution."""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

from ssl_manager.models import (
    AcmeConfig,
    AliyunCredential,
    AppConfig,
    DomainConfig,
    Options,
    ServerConfig,
)

_ENV_PATTERN = re.compile(r"\$\{(\w+)\}")

# Config search order: explicit path > env var > default locations
_DEFAULT_PATHS = [
    Path("config/config.yaml"),
    Path("config.yaml"),
]


def _substitute_env_vars(value: str) -> str:
    """Replace ${ENV_VAR} placeholders with actual environment variable values."""

    def _replace(match: re.Match) -> str:
        var_name = match.group(1)
        env_val = os.environ.get(var_name)
        if env_val is None:
            raise EnvironmentError(
                f"Environment variable '{var_name}' is not set. "
                f"Please set it before running."
            )
        return env_val

    return _ENV_PATTERN.sub(_replace, value)


def _process_value(value):
    """Recursively process config values, substituting env vars in strings."""
    if isinstance(value, str):
        return _substitute_env_vars(value)
    if isinstance(value, dict):
        return {k: _process_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_process_value(item) for item in value]
    return value


def _find_config_file(config_path: str | None = None) -> Path:
    """Locate config file by priority: explicit > env > defaults."""
    if config_path:
        p = Path(config_path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        return p

    env_path = os.environ.get("ALIYUN_SSL_CONFIG")
    if env_path:
        p = Path(env_path)
        if not p.exists():
            raise FileNotFoundError(
                f"Config file from ALIYUN_SSL_CONFIG not found: {env_path}"
            )
        return p

    # Search in multiple base dirs: cwd first, then skill root (relative to package)
    # __file__ -> ssl_manager -> scripts -> get-ssl-ali (3 levels)
    pkg_project_dir = Path(__file__).resolve().parent.parent.parent
    search_bases = [Path.cwd(), pkg_project_dir]

    tried = []
    for base in search_bases:
        for rel in _DEFAULT_PATHS:
            candidate = base / rel
            tried.append(str(candidate))
            if candidate.exists():
                return candidate

    raise FileNotFoundError(
        f"No config file found. Tried: {', '.join(tried)}. "
        f"Set ALIYUN_SSL_CONFIG env var or use --config flag."
    )


def load_config(config_path: str | None = None) -> AppConfig:
    """Load and validate config from YAML file.

    Args:
        config_path: Explicit path to config file. If None, auto-discover.

    Returns:
        Fully validated AppConfig with env vars resolved.
    """
    path = _find_config_file(config_path)
    config_base_dir = path.resolve().parent.parent  # config/ -> project root
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    data = _process_value(raw)

    # Build credential
    aliyun_section = data.get("aliyun", {})
    credential = AliyunCredential(
        access_key_id=aliyun_section["access_key_id"],
        access_key_secret=aliyun_section["access_key_secret"],
    )

    # Build cert storage dir (resolve relative paths against skill root)
    storage = data.get("cert_storage", {})
    cert_dir_raw = storage.get("base_dir", "./certs")
    cert_dir = str((config_base_dir / cert_dir_raw).resolve())

    # Build domain configs
    domains = []
    for d in data.get("domains", []):
        servers = []
        for s in d.get("servers", []):
            servers.append(
                ServerConfig(
                    host=s["host"],
                    port=s.get("port", 22),
                    user=s.get("user", "root"),
                    password=s["password"],
                    cert_path=s["cert_path"],
                    key_path=s["key_path"],
                    reload_cmd=s.get(
                        "reload_cmd", "nginx -t && systemctl reload nginx"
                    ),
                )
            )
        domains.append(DomainConfig(
            domain=d["domain"],
            servers=servers,
            san=d.get("san", []),
            challenge_type=d.get("challenge_type"),
        ))

    # Build options
    opts_raw = data.get("options", {})
    options = Options(
        poll_interval=opts_raw.get("poll_interval", 10),
        poll_timeout=opts_raw.get("poll_timeout", 300),
        renew_before_days=opts_raw.get("renew_before_days", 14),
        backup_old_cert=opts_raw.get("backup_old_cert", True),
        max_cert_validity_days=opts_raw.get("max_cert_validity_days", 199),
    )

    # Build ACME config (required for certificate issuance)
    acme_raw = data.get("acme", {})
    acme_key_raw = acme_raw.get("account_key_path", "./certs/acme_account.key")
    acme_key_path = str((config_base_dir / acme_key_raw).resolve())
    acme_config = AcmeConfig(
        enabled=acme_raw.get("enabled", False),
        directory_url=acme_raw.get(
            "directory_url",
            "https://acme-v02.api.letsencrypt.org/directory",
        ),
        email=acme_raw.get("email", ""),
        account_key_path=acme_key_path,
        challenge_type=acme_raw.get("challenge_type", "dns-01"),
    )

    return AppConfig(
        aliyun=credential,
        cert_storage_dir=cert_dir,
        domains=domains,
        options=options,
        acme=acme_config,
    )
