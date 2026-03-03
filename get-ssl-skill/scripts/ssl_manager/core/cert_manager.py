"""Certificate lifecycle manager - orchestrates the 6-step ACME flow.

All certificate issuance goes through ACME (Let's Encrypt) with DNS-01
validation via Aliyun DNS API. CAS API is only used read-only for
querying legacy certificate records.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ssl_manager.api.cas_client import CasClient
from ssl_manager.api.dns_client import DnsClient
from ssl_manager.models import AppConfig, safe_dirname
from ssl_manager.utils.logger import log


def _parse_cert_time(raw_time) -> datetime | None:
    """Parse certificate timestamp, handling both string dates and epoch millis.

    Args:
        raw_time: String date, epoch millis (int/str), or None.

    Returns:
        datetime object (UTC) or None if unparseable.
    """
    if raw_time is None:
        return None

    if isinstance(raw_time, (int, float)):
        try:
            return datetime.fromtimestamp(raw_time / 1000, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None

    if isinstance(raw_time, str):
        try:
            ts = int(raw_time)
            if ts > 1_000_000_000_000:
                return datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
        except ValueError:
            pass

        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d"):
            try:
                return datetime.strptime(raw_time, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue

    return None


def _format_cert_time(raw_time) -> str:
    """Format raw cert time to human-readable string."""
    dt = _parse_cert_time(raw_time)
    if dt is None:
        return str(raw_time) if raw_time is not None else "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


class CertManager:
    """Orchestrates certificate check / apply / deploy / renew / diagnose.

    Uses ACME (Let's Encrypt) exclusively for certificate issuance.
    DNS-01 validation via Aliyun DNS API.
    """

    def __init__(self, config: AppConfig):
        self._config = config
        self._cas = CasClient(credential=config.aliyun)
        self._dns = DnsClient(config.aliyun)

    # ── check ────────────────────────────────────────────────────

    def check(self, domain: str | None = None) -> None:
        """Check ACME status and existing certificate expiry."""
        print("=" * 60)
        print("  SSL Certificate Status Check")
        print("=" * 60)

        # ACME status
        print("\n  [ACME Mode]")
        if self._config.acme.enabled:
            print(f"    Status: ENABLED")
            print(f"    Directory: {self._config.acme.directory_url}")
            print(f"    Email: {self._config.acme.email}")
            print(f"    Account key: {self._config.acme.account_key_path}")
            from ssl_manager.api.acme_client import AcmeClient
            acme = AcmeClient(self._config.acme)
            result = acme.check_connectivity()
            if result["ok"]:
                print(f"    Connectivity: OK")
            else:
                print(f"    Connectivity: FAILED - {result.get('error', 'unknown')}")
        else:
            print(f"    Status: DISABLED")
            print(f"    Set acme.enabled=true in config.yaml to enable")

        # Check existing certificates
        domains_to_check = (
            [domain] if domain else self._config.list_domains()
        )

        print(f"\n  Checking {len(domains_to_check)} domain(s)...")
        print("-" * 60)

        for d in domains_to_check:
            self._check_domain_certs(d)

        print("=" * 60)

    def _check_local_cert(self, domain: str) -> bool:
        """Check local certificate file and print its details.

        Returns:
            True if local cert was found and displayed, False otherwise.
        """
        cert_file = Path(self._config.cert_storage_dir) / safe_dirname(domain) / "fullchain.pem"
        if not cert_file.exists():
            return False

        try:
            from cryptography import x509 as cx509

            cert_data = cert_file.read_bytes()
            cert = cx509.load_pem_x509_certificate(cert_data)

            issuer = cert.issuer
            try:
                from cryptography.x509.oid import NameOID
                issuer_cn = issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                issuer_o = issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                issuer_name = (
                    issuer_cn[0].value if issuer_cn
                    else issuer_o[0].value if issuer_o
                    else str(issuer)
                )
            except Exception:
                issuer_name = str(issuer)

            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
            now_utc = datetime.now(tz=timezone.utc)
            delta = not_after - now_utc
            days_left = delta.days

            needs_renew = days_left <= self._config.options.renew_before_days
            renew_flag = " *** NEEDS RENEWAL ***" if needs_renew else ""

            print(f"\n  {domain}:")
            print(f"    Source:  Local ({cert_file})")
            print(f"    Issuer:  {issuer_name}")
            print(f"    From:    {not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            print(f"    Expires: {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')} ({days_left} days){renew_flag}")
            return True

        except Exception as e:
            print(f"\n  {domain}: Local cert parse error - {e}")
            return False

    def _check_domain_certs(self, domain: str) -> None:
        """Check certificate status for a single domain.

        Priority: local fullchain.pem first, then fallback to Aliyun CAS records.
        """
        if self._check_local_cert(domain):
            return

        # Fallback: query Aliyun CAS records (legacy certificates)
        try:
            orders = self._cas.list_user_certificates(keyword=domain)
            if not orders:
                print(f"\n  {domain}: No certificates found (local or CAS)")
                return

            for order in orders:
                if order.get("domain") and domain not in order["domain"]:
                    continue
                status = order.get("status", "unknown")
                end_time_raw = order.get("cert_end_time")

                days_left = "N/A"
                needs_renew = False
                end_dt = _parse_cert_time(end_time_raw)
                if end_dt:
                    now_utc = datetime.now(tz=timezone.utc)
                    delta = end_dt - now_utc
                    days_left = f"{delta.days} days"
                    needs_renew = delta.days <= self._config.options.renew_before_days

                renew_flag = " *** NEEDS RENEWAL ***" if needs_renew else ""
                display_time = _format_cert_time(end_time_raw)
                print(f"\n  {order.get('domain', domain)}:")
                print(f"    Source:  Aliyun CAS (legacy)")
                print(f"    Status:  {status}")
                print(f"    Expires: {display_time} ({days_left}){renew_flag}")
                print(f"    OrderID: {order.get('order_id', 'N/A')}")

        except Exception as e:
            print(f"\n  {domain}: Error checking - {e}")

    # ── apply ────────────────────────────────────────────────────

    def apply(self, domain: str, dry_run: bool = False) -> None:
        """Apply for a new certificate via ACME (Let's Encrypt)."""
        dc = self._config.get_domain(domain)
        if not dc:
            log.error(f"Domain '{domain}' not found in config")
            return

        if not self._config.acme.enabled:
            log.error(
                "ACME is not enabled! Set acme.enabled=true in config.yaml"
            )
            return

        if dry_run:
            self._show_apply_plan(dc)
            return

        self._execute_apply(domain)

    def _show_apply_plan(self, dc) -> None:
        """Show what apply would do without executing."""
        print("=" * 60)
        print("  Certificate Apply Plan (DRY RUN)")
        print("=" * 60)
        print(f"\n  Domain: {dc.domain}")
        if dc.san:
            print(f"  SAN:    {', '.join(dc.san)}")
        print(f"  Mode: ACME (Let's Encrypt via {self._config.acme.directory_url})")
        print(f"\n  Steps:")
        print(f"    [1/6] Register/load ACME account")
        print(f"    [2/6] Create ACME order + get dns-01 challenge(s)")
        print(f"    [3/6] Add TXT DNS validation record(s) (Aliyun DNS)")
        print(f"    [4/6] Answer ACME challenge(s)")
        print(f"    [5/6] Poll ACME order until valid (up to {self._config.options.poll_timeout}s)")
        print(f"    [6/6] Finalize + download cert + cleanup DNS")
        print(f"\n  Storage: {self._config.cert_storage_dir}/{safe_dirname(dc.domain)}/")
        print("=" * 60)

    def _resolve_challenge_type(self, domain: str) -> str:
        """Determine challenge type for a domain.

        Priority: domain-level override > global ACME config default.
        """
        dc = self._config.get_domain(domain)
        if dc and dc.challenge_type:
            return dc.challenge_type
        return self._config.acme.challenge_type

    def _execute_apply(self, domain: str) -> dict | None:
        """Route to the appropriate apply flow based on challenge type."""
        challenge_type = self._resolve_challenge_type(domain)
        if challenge_type == "dns-persist-01":
            return self._execute_apply_persist(domain)
        return self._execute_apply_dns01(domain)

    def _execute_apply_dns01(self, domain: str) -> dict | None:
        """Execute the 6-step ACME dns-01 certificate application flow.

        Supports wildcard domains and SAN lists. Multiple authorizations
        are handled by iterating all dns-01 challenges.

        Returns:
            dict with cert/key paths if successful, None on failure.
        """
        from ssl_manager.api.acme_client import AcmeClient
        from ssl_manager.core.validator import DnsValidator

        dc = self._config.get_domain(domain)
        san = dc.san if dc else []

        acme = AcmeClient(self._config.acme)
        log.set_total_steps(6)

        # [1/6] Register ACME account
        log.step("Registering/loading ACME account")
        try:
            acme.register_or_load()
            log.success(f"ACME account ready ({self._config.acme.directory_url})")
        except Exception as e:
            log.error(f"ACME account registration failed: {e!r}")
            return None

        # [2/6] Create order + get dns-01 challenges
        log.step("Creating ACME order and getting dns-01 challenge(s)")
        try:
            order, challenge_list = acme.request_certificate(domain, san=san or None)
            for ci in challenge_list:
                log.success(
                    f"dns-01 challenge: {ci['record_name']} "
                    f"TXT = {ci['validation'][:32]}..."
                )
        except Exception as e:
            log.error(f"ACME order failed: {e!r}")
            return None

        # [3/6] Add DNS TXT record(s) via Aliyun DNS
        log.step("Adding DNS validation record(s) via Aliyun DNS")
        validator = DnsValidator(self._dns)
        dns_records: list[tuple[str, str]] = []  # (root_domain, rr) for cleanup
        try:
            for ci in challenge_list:
                root_domain, rr = validator.parse_record_domain(
                    ci["record_name"], ci["domain"]
                )
                validator.add_validation_record(
                    root_domain=root_domain,
                    rr=rr,
                    record_type="TXT",
                    value=ci["validation"],
                )
                dns_records.append((root_domain, rr))
                log.success(f"DNS record added: {rr}.{root_domain}")
        except Exception as e:
            log.error(f"Failed to add DNS record: {e}")
            return None

        # [4/6] Answer ACME challenges
        log.step("Answering ACME challenge(s)")
        try:
            for ci in challenge_list:
                acme.answer_challenge(ci["challenge_body"])
            log.success("All challenges answered, ACME server will verify DNS")
        except Exception as e:
            log.error(f"Failed to answer challenge: {e}")
            return None

        # [5/6] Poll ACME order + finalize + download cert
        log.step(
            f"Polling ACME order and finalizing (timeout={self._config.options.poll_timeout}s)"
        )
        try:
            fullchain_pem, private_key_pem = acme.poll_and_finalize(
                order, timeout=self._config.options.poll_timeout
            )
            log.success("Certificate issued by Let's Encrypt!")
        except TimeoutError:
            log.error(
                f"Timed out after {self._config.options.poll_timeout}s. "
                "DNS propagation may be slow. Try again later."
            )
            return None
        except RuntimeError as e:
            log.error(str(e))
            return None
        except Exception as e:
            log.error(f"ACME finalization failed: {e!r}")
            return None

        # [6/6] Save certificate + cleanup DNS
        log.step("Saving certificate and cleaning up DNS")
        try:
            cert_dir = Path(self._config.cert_storage_dir) / safe_dirname(domain)
            cert_dir.mkdir(parents=True, exist_ok=True)

            cert_path = cert_dir / "fullchain.pem"
            key_path = cert_dir / "privkey.pem"

            cert_path.write_text(fullchain_pem, encoding="utf-8")
            key_path.write_text(private_key_pem, encoding="utf-8")
            log.success(f"Certificate saved to {cert_dir}")

            # Cleanup all DNS validation records
            for root_domain, rr in dns_records:
                try:
                    validator.cleanup(root_domain, rr, "TXT")
                except Exception as e:
                    log.warn(f"DNS cleanup failed for {rr}.{root_domain} (non-critical): {e}")

            return {
                "cert_path": str(cert_path),
                "key_path": str(key_path),
                "domain": domain,
            }

        except Exception as e:
            log.error(f"Failed to save certificate: {e}")
            return None

    def _execute_apply_persist(self, domain: str) -> dict | None:
        """Execute simplified ACME flow using dns-persist-01.

        Assumes persistent DNS record is already in place (via ``setup_persist``).
        Steps: register → create order → answer challenge → poll+save

        Returns:
            dict with cert/key paths if successful, None on failure.
        """
        from ssl_manager.api.acme_client import AcmeClient

        dc = self._config.get_domain(domain)
        san = dc.san if dc else []

        acme = AcmeClient(self._config.acme)
        log.set_total_steps(4)

        # [1/4] Register ACME account
        log.step("Registering/loading ACME account")
        try:
            acme.register_or_load()
            log.success(f"ACME account ready ({self._config.acme.directory_url})")
        except Exception as e:
            log.error(f"ACME account registration failed: {e!r}")
            return None

        # [2/4] Create order + find challenges (prefer dns-persist-01)
        log.step("Creating ACME order (dns-persist-01 mode)")
        try:
            order, challenge_list = acme.request_certificate(domain, san=san or None)
            # Re-discover with persist preference
            challenge_list = acme.find_challenges(order, preferred_type="dns-persist-01")
            for ci in challenge_list:
                ctype = ci.get("_type", "dns-01")
                log.success(f"Challenge ({ctype}) found for {ci['domain']}")
        except Exception as e:
            log.error(f"ACME order failed: {e!r}")
            return None

        # [3/4] Answer challenges (no DNS modification needed for persist)
        log.step("Answering challenge(s) (persistent record already in DNS)")
        try:
            for ci in challenge_list:
                if ci.get("_type") == "dns-persist-01":
                    acme.answer_persist_challenge(ci["challenge_body"])
                else:
                    acme.answer_challenge(ci["challenge_body"])
            log.success("All challenges answered")
        except Exception as e:
            log.error(f"Failed to answer challenge: {e}")
            return None

        # [4/4] Poll + finalize + save
        log.step(
            f"Polling ACME order and finalizing (timeout={self._config.options.poll_timeout}s)"
        )
        try:
            fullchain_pem, private_key_pem = acme.poll_and_finalize(
                order, timeout=self._config.options.poll_timeout
            )
            log.success("Certificate issued by Let's Encrypt!")
        except TimeoutError:
            log.error(
                f"Timed out after {self._config.options.poll_timeout}s. "
                "Persistent DNS record may be incorrect. Check with diagnose."
            )
            return None
        except RuntimeError as e:
            log.error(str(e))
            return None
        except Exception as e:
            log.error(f"ACME finalization failed: {e!r}")
            return None

        # Save certificate
        try:
            cert_dir = Path(self._config.cert_storage_dir) / safe_dirname(domain)
            cert_dir.mkdir(parents=True, exist_ok=True)

            cert_path = cert_dir / "fullchain.pem"
            key_path = cert_dir / "privkey.pem"

            cert_path.write_text(fullchain_pem, encoding="utf-8")
            key_path.write_text(private_key_pem, encoding="utf-8")
            log.success(f"Certificate saved to {cert_dir}")

            return {
                "cert_path": str(cert_path),
                "key_path": str(key_path),
                "domain": domain,
            }
        except Exception as e:
            log.error(f"Failed to save certificate: {e}")
            return None

    # ── setup-persist ─────────────────────────────────────────

    def setup_persist(
        self,
        domain: str,
        *,
        policy: str | None = None,
        persist_until: int | None = None,
        dry_run: bool = False,
    ) -> None:
        """Set up a persistent DNS validation record for dns-persist-01.

        This needs to be done once per domain. After setup, all future
        renewals using dns-persist-01 will skip DNS modification.

        Args:
            domain: Target domain (may be wildcard).
            policy: Optional policy (e.g. ``"wildcard"``).
            persist_until: Optional UNIX timestamp for record expiry.
            dry_run: If True, show what would be done.
        """
        if not self._config.acme.enabled:
            log.error("ACME is not enabled! Set acme.enabled=true in config.yaml")
            return

        from ssl_manager.api.acme_client import AcmeClient
        from ssl_manager.core.validator import PersistValidator

        acme = AcmeClient(self._config.acme)

        # Register to get account URI
        try:
            acme.register_or_load()
        except Exception as e:
            log.error(f"ACME account registration failed: {e!r}")
            return

        account_uri = acme.get_account_uri()
        pv = PersistValidator(self._dns)
        root_domain, rr = pv.get_record_domain(domain)
        value = pv.build_record_value(
            self._config.acme.directory_url,
            account_uri,
            policy=policy,
            persist_until=persist_until,
        )

        if dry_run:
            print("=" * 60)
            print("  DNS-PERSIST-01 Setup Plan (DRY RUN)")
            print("=" * 60)
            print(f"\n  Domain:  {domain}")
            print(f"  Record:  {rr}.{root_domain}")
            print(f"  Type:    TXT")
            print(f"  Value:   {value}")
            if policy:
                print(f"  Policy:  {policy}")
            if persist_until:
                print(f"  Persist until: {persist_until}")
            print(f"\n  Account URI: {account_uri}")
            print("=" * 60)
            return

        pv.setup_persist_record(
            domain,
            self._config.acme.directory_url,
            account_uri,
            policy=policy,
            persist_until=persist_until,
        )
        log.success(f"Persistent DNS record set up for {domain}")

    # ── deploy ───────────────────────────────────────────────────

    def deploy(
        self, domain: str, server: str | None = None, dry_run: bool = False
    ) -> None:
        """Deploy certificate to server(s)."""
        dc = self._config.get_domain(domain)
        if not dc:
            log.error(f"Domain '{domain}' not found in config")
            return

        cert_dir = Path(self._config.cert_storage_dir) / safe_dirname(domain)
        cert_path = cert_dir / "fullchain.pem"
        key_path = cert_dir / "privkey.pem"

        if not cert_path.exists() or not key_path.exists():
            log.error(
                f"Local certificate files not found in {cert_dir}. "
                f"Run 'apply --domain {domain}' first."
            )
            return

        servers = dc.servers
        if server:
            servers = [s for s in servers if s.host == server]
            if not servers:
                log.error(f"Server '{server}' not found for domain {domain}")
                return

        if dry_run:
            self._show_deploy_plan(domain, servers, cert_path, key_path)
            return

        self._execute_deploy(domain, servers, cert_path, key_path)

    def _show_deploy_plan(self, domain, servers, cert_path, key_path) -> None:
        """Show deploy plan without executing."""
        print("=" * 60)
        print("  Certificate Deploy Plan (DRY RUN)")
        print("=" * 60)
        print(f"\n  Domain: {domain}")
        print(f"  Local cert: {cert_path}")
        print(f"  Local key:  {key_path}")
        print(f"  Backup old: {self._config.options.backup_old_cert}")
        print(f"\n  Target servers ({len(servers)}):")
        for s in servers:
            print(f"    - {s.user}@{s.host}:{s.port}")
            print(f"      cert -> {s.cert_path}")
            print(f"      key  -> {s.key_path}")
            print(f"      then: {s.reload_cmd}")
        print("=" * 60)

    def _execute_deploy(self, domain, servers, cert_path, key_path) -> None:
        """Execute deployment to all target servers."""
        from ssl_manager.core.deployer import Deployer

        deployer = Deployer(backup=self._config.options.backup_old_cert)
        success_count = 0

        for s in servers:
            log.info(f"Deploying to {s.user}@{s.host}:{s.port}")
            try:
                deployer.deploy(
                    server=s,
                    local_cert=str(cert_path),
                    local_key=str(key_path),
                )
                success_count += 1
                log.success(f"Deploy to {s.host} completed")
            except Exception as e:
                log.error(f"Deploy to {s.host} failed: {e}")

        total = len(servers)
        if success_count == total:
            log.success(f"All {total} server(s) deployed successfully for {domain}")
        else:
            log.warn(f"{success_count}/{total} server(s) deployed for {domain}")

    # ── renew ────────────────────────────────────────────────────

    def renew(self, domain: str | None = None, dry_run: bool = False) -> None:
        """Batch renew: check expiry -> apply -> deploy for due domains."""
        domains_to_check = (
            [domain] if domain else self._config.list_domains()
        )

        domains_to_renew = []
        for d in domains_to_check:
            if self._needs_renewal(d):
                domains_to_renew.append(d)

        if not domains_to_renew:
            print("No domains need renewal at this time.")
            return

        print(f"\n  Domains needing renewal: {len(domains_to_renew)}")
        for d in domains_to_renew:
            print(f"    - {d}")
        print()

        if dry_run:
            for d in domains_to_renew:
                dc = self._config.get_domain(d)
                if dc:
                    self._show_apply_plan(dc)
                    self._show_deploy_plan(
                        d, dc.servers,
                        Path(self._config.cert_storage_dir) / safe_dirname(d) / "fullchain.pem",
                        Path(self._config.cert_storage_dir) / safe_dirname(d) / "privkey.pem",
                    )
            return

        for d in domains_to_renew:
            print(f"\n{'='*60}")
            print(f"  Renewing: {d}")
            print(f"{'='*60}")

            result = self._execute_apply(d)
            if result:
                dc = self._config.get_domain(d)
                if dc and dc.servers:
                    self._execute_deploy(
                        d, dc.servers,
                        Path(result["cert_path"]),
                        Path(result["key_path"]),
                    )

    def _needs_renewal(self, domain: str) -> bool:
        """Check if a domain's certificate needs renewal.

        Checks local certificate files first, then falls back to CAS records.
        """
        cert_file = Path(self._config.cert_storage_dir) / safe_dirname(domain) / "fullchain.pem"
        if cert_file.exists():
            try:
                from cryptography import x509 as cx509

                cert_data = cert_file.read_bytes()
                cert = cx509.load_pem_x509_certificate(cert_data)
                now_utc = datetime.now(tz=timezone.utc)
                delta = cert.not_valid_after_utc - now_utc
                if delta.days > self._config.options.renew_before_days:
                    return False
            except Exception:
                pass

        # Fallback: check legacy CAS records
        try:
            orders = self._cas.list_user_certificates(keyword=domain)
            if not orders:
                return True

            for order in orders:
                if order.get("domain") and domain not in order.get("domain", ""):
                    continue
                end_time_raw = order.get("cert_end_time")
                if not end_time_raw:
                    continue

                end_dt = _parse_cert_time(end_time_raw)
                if not end_dt:
                    continue

                now_utc = datetime.now(tz=timezone.utc)
                delta = end_dt - now_utc
                if delta.days > self._config.options.renew_before_days:
                    return False

            return True
        except Exception:
            return True

    # ── diagnose ─────────────────────────────────────────────────

    def diagnose(self) -> None:
        """Diagnose ACME connectivity, challenge config, and Aliyun API status."""
        print("=" * 60)
        print("  SSL Certificate Diagnostic Report")
        print("=" * 60)

        # Phase 1: ACME status + challenge type
        print("\n  [1/4] ACME (Let's Encrypt) status...")
        if self._config.acme.enabled:
            print(f"    ENABLED")
            print(f"    Directory: {self._config.acme.directory_url}")
            print(f"    Email: {self._config.acme.email}")
            print(f"    Account key: {self._config.acme.account_key_path}")
            print(f"    Challenge type (global): {self._config.acme.challenge_type}")
            from ssl_manager.api.acme_client import AcmeClient
            acme = AcmeClient(self._config.acme)
            conn = acme.check_connectivity()
            if conn["ok"]:
                print(f"    Connectivity: OK (endpoints: {', '.join(conn['endpoints'][:4])})")
                key_path = Path(self._config.acme.account_key_path)
                print(f"    Account key exists: {'YES' if key_path.exists() else 'NO (will be created on first use)'}")
            else:
                print(f"    Connectivity: FAILED - {conn.get('error', 'unknown')}")
        else:
            print(f"    DISABLED (set acme.enabled=true in config.yaml to enable)")

        # Phase 2: Per-domain challenge type + persist record status
        print("\n  [2/4] Domain challenge configuration...")
        from ssl_manager.core.validator import PersistValidator
        pv = PersistValidator(self._dns)
        for dc in self._config.domains:
            ctype = self._resolve_challenge_type(dc.domain)
            san_info = f" + SAN: {', '.join(dc.san)}" if dc.san else ""
            print(f"    {dc.domain}{san_info}")
            print(f"      Challenge type: {ctype}")
            if ctype == "dns-persist-01":
                records = pv.check_persist_record(dc.domain)
                if records:
                    print(f"      Persist record: FOUND ({len(records)} record(s))")
                    for r in records[:2]:
                        val = r.get("Value", r.get("value", "?"))
                        print(f"        TXT = {val[:60]}...")
                else:
                    print(f"      Persist record: NOT FOUND - run 'setup-persist --domain {dc.domain}'")

        # Phase 3: Aliyun API connectivity (read-only)
        print("\n  [3/4] Testing Aliyun API connectivity...")
        try:
            certs = self._cas.list_user_certificates()
            print(f"    CAS API: OK - found {len(certs)} certificate record(s)")
            if certs:
                for c in certs[:3]:
                    end_display = _format_cert_time(c.get("cert_end_time"))
                    print(f"    - {c.get('domain', '?')}: status={c.get('status', '?')}, expires={end_display}")
                if len(certs) > 3:
                    print(f"    ... and {len(certs) - 3} more")
        except Exception as e:
            print(f"    CAS API: FAILED - {e}")

        # Phase 4: Recommendations
        print("\n  [4/4] Recommendations:")
        if self._config.acme.enabled:
            print(f"\n    ACME mode is ACTIVE")
            print(f"    Certificates will be issued by Let's Encrypt.")
            print(f"    DNS validation via Aliyun DNS API.")
            if self._config.acme.challenge_type == "dns-persist-01":
                print(f"    dns-persist-01 is the default challenge type.")
                print(f"    Make sure to run 'setup-persist' for each domain first.")
        else:
            print(f"\n    ACME is DISABLED!")
            print(f"    Enable it in config.yaml:")
            print(f"    acme:")
            print(f"      enabled: true")
            print(f"      email: 'you@example.com'")

        print("=" * 60)
