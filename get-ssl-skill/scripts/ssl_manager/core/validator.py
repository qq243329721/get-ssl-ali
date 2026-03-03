"""DNS validation record management."""

from __future__ import annotations

from ssl_manager.api.dns_client import DnsClient
from ssl_manager.models import strip_wildcard
from ssl_manager.utils.logger import log


class DnsValidator:
    """Manages DNS validation records for certificate issuance."""

    def __init__(self, dns_client: DnsClient):
        self._dns = dns_client

    @staticmethod
    def parse_record_domain(record_domain: str, target_domain: str) -> tuple[str, str]:
        """Parse the full record domain into root domain and RR (host record).

        The ACME DNS-01 challenge requires a TXT record like
        "_acme-challenge.example.com" or "_acme-challenge.sub.example.com".
        We need to split it into:
        - root_domain: the registered domain (e.g. "example.com")
        - rr: the host record (e.g. "_acme-challenge" or "_acme-challenge.sub")

        Wildcard domains (``*.example.com``) are stripped before extraction
        so that ``_acme-challenge.*.example.com`` never appears.

        Args:
            record_domain: Full validation domain for DNS-01 challenge.
            target_domain: The domain being validated (may be wildcard).

        Returns:
            Tuple of (root_domain, rr).
        """
        # Strip wildcard prefix before extracting root domain
        base_domain = strip_wildcard(target_domain)

        # Extract root domain from base: if base is "sub.example.com",
        # root is "example.com" (last two parts)
        parts = base_domain.split(".")
        if len(parts) >= 2:
            root_domain = ".".join(parts[-2:])
        else:
            root_domain = base_domain

        # The RR is everything before the root domain in record_domain
        if record_domain.endswith("." + root_domain):
            rr = record_domain[: -(len(root_domain) + 1)]
        elif record_domain.endswith(root_domain):
            rr = record_domain[: -len(root_domain)].rstrip(".")
        else:
            # Fallback: use the full record_domain as rr
            rr = record_domain
            log.warn(
                f"Could not parse root domain from '{record_domain}', "
                f"using full value as RR"
            )

        return root_domain, rr

    def add_validation_record(
        self,
        root_domain: str,
        rr: str,
        record_type: str,
        value: str,
    ) -> str:
        """Add a DNS validation record, cleaning up any existing duplicates first.

        Args:
            root_domain: The root domain (e.g. "example.com").
            rr: Host record (e.g. "_dnsauth").
            record_type: Record type (usually "TXT").
            value: Validation value.

        Returns:
            The new record ID.
        """
        # Clean up old validation records with same RR
        try:
            self._dns.cleanup_validation_records(root_domain, rr, record_type)
        except Exception as e:
            log.warn(f"Cleanup of old records failed (non-critical): {e}")

        # Add new validation record
        return self._dns.add_record(
            domain=root_domain,
            rr=rr,
            record_type=record_type,
            value=value,
        )

    def cleanup(self, root_domain: str, rr: str, record_type: str = "TXT") -> None:
        """Clean up validation DNS records.

        Args:
            root_domain: The root domain.
            rr: Host record to clean.
            record_type: Record type to clean.
        """
        self._dns.cleanup_validation_records(root_domain, rr, record_type)


class PersistValidator:
    """Manages dns-persist-01 persistent DNS records.

    DNS-PERSIST-01 is a new ACME challenge type where the DNS record is
    set once and reused for all future renewals, removing the need to
    modify DNS on every certificate cycle.

    Record format:
        ``_validation-persist.{domain}  TXT  "letsencrypt.org; accounturi=..."``
    """

    DNS_LABEL = "_validation-persist"

    def __init__(self, dns_client: DnsClient):
        self._dns = dns_client

    @staticmethod
    def build_record_value(
        directory_url: str,
        account_uri: str,
        *,
        policy: str | None = None,
        persist_until: int | None = None,
    ) -> str:
        """Build the TXT record value for a persist record.

        Format: ``"letsencrypt.org; accounturi=https://...acct/123"``
        Optional: ``"; policy=wildcard"`` / ``"; persistUntil=UNIX_TS"``

        Args:
            directory_url: ACME directory URL (used to extract issuer domain).
            account_uri: Full ACME account URI.
            policy: Optional policy string (e.g. ``"wildcard"``).
            persist_until: Optional UNIX timestamp for record expiry.

        Returns:
            The formatted TXT record value.
        """
        # Extract issuer domain from directory URL
        from urllib.parse import urlparse
        issuer = urlparse(directory_url).hostname or "letsencrypt.org"

        value = f"{issuer}; accounturi={account_uri}"
        if policy:
            value += f"; policy={policy}"
        if persist_until is not None:
            value += f"; persistUntil={persist_until}"
        return value

    def get_record_domain(self, target_domain: str) -> tuple[str, str]:
        """Compute root_domain and RR for a persist record.

        Args:
            target_domain: The domain to protect (may be wildcard).

        Returns:
            Tuple of (root_domain, rr) suitable for Aliyun DNS API.
        """
        base_domain = strip_wildcard(target_domain)
        parts = base_domain.split(".")
        if len(parts) >= 2:
            root_domain = ".".join(parts[-2:])
        else:
            root_domain = base_domain

        full_record = f"{self.DNS_LABEL}.{base_domain}"
        if full_record.endswith("." + root_domain):
            rr = full_record[: -(len(root_domain) + 1)]
        else:
            rr = self.DNS_LABEL

        return root_domain, rr

    def setup_persist_record(
        self,
        target_domain: str,
        directory_url: str,
        account_uri: str,
        *,
        policy: str | None = None,
        persist_until: int | None = None,
    ) -> str:
        """Create a persistent validation DNS record.

        Args:
            target_domain: Domain to protect.
            directory_url: ACME directory URL.
            account_uri: ACME account URI.
            policy: Optional policy (e.g. ``"wildcard"``).
            persist_until: Optional UNIX timestamp.

        Returns:
            The new record ID.
        """
        root_domain, rr = self.get_record_domain(target_domain)
        value = self.build_record_value(
            directory_url, account_uri,
            policy=policy, persist_until=persist_until,
        )

        # Clean up any existing persist records first
        try:
            self._dns.cleanup_validation_records(root_domain, rr, "TXT")
        except Exception as e:
            log.warn(f"Cleanup of old persist records failed (non-critical): {e}")

        record_id = self._dns.add_record(
            domain=root_domain,
            rr=rr,
            record_type="TXT",
            value=value,
        )
        log.success(
            f"Persist record created: {rr}.{root_domain} TXT = {value[:60]}..."
        )
        return record_id

    def check_persist_record(self, target_domain: str) -> list[dict]:
        """Query existing persist records for a domain.

        Returns:
            List of matching DNS record dicts (may be empty).
        """
        root_domain, rr = self.get_record_domain(target_domain)
        try:
            return self._dns.find_records(root_domain, rr=rr, record_type="TXT")
        except Exception:
            return []

    def remove_persist_record(self, target_domain: str) -> int:
        """Remove all persist records for a domain.

        Returns:
            Number of records removed.
        """
        root_domain, rr = self.get_record_domain(target_domain)
        return self._dns.cleanup_validation_records(root_domain, rr, "TXT")
