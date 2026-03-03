"""Data models for SSL certificate management."""

from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Wildcard domain helpers
# ---------------------------------------------------------------------------

def safe_dirname(domain: str) -> str:
    """Convert domain to a filesystem-safe directory name.

    ``*.example.com`` -> ``_wildcard.example.com``
    """
    return domain.replace("*", "_wildcard")


def is_wildcard(domain: str) -> bool:
    """Return True if *domain* is a wildcard (e.g. ``*.example.com``)."""
    return domain.startswith("*.")


def strip_wildcard(domain: str) -> str:
    """Strip the wildcard prefix: ``*.example.com`` -> ``example.com``."""
    return domain[2:] if is_wildcard(domain) else domain


@dataclass
class ServerConfig:
    """Single server deployment target."""

    host: str
    port: int
    user: str
    password: str
    cert_path: str
    key_path: str
    reload_cmd: str = "nginx -t && systemctl reload nginx"


@dataclass
class DomainConfig:
    """Domain with its deployment servers."""

    domain: str
    servers: list[ServerConfig] = field(default_factory=list)
    san: list[str] = field(default_factory=list)
    challenge_type: str | None = None  # per-domain override ("dns-01" | "dns-persist-01")


@dataclass
class AliyunCredential:
    """Alibaba Cloud API credentials."""

    access_key_id: str
    access_key_secret: str


@dataclass
class Options:
    """Global options for the manager."""

    poll_interval: int = 10
    poll_timeout: int = 300
    renew_before_days: int = 14
    backup_old_cert: bool = True
    max_cert_validity_days: int = 199


@dataclass
class AcmeConfig:
    """ACME certificate provider configuration (Let's Encrypt / ZeroSSL)."""

    enabled: bool = False
    directory_url: str = "https://acme-v02.api.letsencrypt.org/directory"
    email: str = ""
    account_key_path: str = "./certs/acme_account.key"
    challenge_type: str = "dns-01"  # global default: "dns-01" | "dns-persist-01"


@dataclass
class AppConfig:
    """Top-level application config."""

    aliyun: AliyunCredential
    cert_storage_dir: str
    domains: list[DomainConfig]
    options: Options
    acme: AcmeConfig = field(default_factory=AcmeConfig)

    def get_domain(self, domain_name: str) -> DomainConfig | None:
        """Find a domain config by name."""
        for d in self.domains:
            if d.domain == domain_name:
                return d
        return None

    def list_domains(self) -> list[str]:
        """Return all configured domain names."""
        return [d.domain for d in self.domains]
