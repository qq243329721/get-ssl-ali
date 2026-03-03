"""ACME protocol client for Let's Encrypt / ZeroSSL certificate issuance.

Uses the ``acme`` library (certbot's underlying lib) + ``josepy`` for JOSE.
Pure Python implementation, no external CLI dependency.

Flow:
    1. register_or_load()          → setup ACME account
    2. request_certificate(domain) → create order + extract dns-01 info
    3. answer_challenge()          → notify server DNS is ready
    4. poll_and_finalize()         → wait + finalize + download cert
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import josepy as jose
from acme import challenges, client, errors as acme_errors, messages
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from ssl_manager.models import AcmeConfig, strip_wildcard
from ssl_manager.utils.logger import log

_USER_AGENT = "ssl-manager/0.1.0"


class AcmeClient:
    """ACME v2 certificate client.

    Wraps the full dns-01 issuance flow against Let's Encrypt or any
    RFC 8555-compliant server.
    """

    def __init__(self, config: AcmeConfig):
        self._config = config
        self._account_key: jose.JWK | None = None
        self._acme_client: client.ClientV2 | None = None
        # Cert private key generated during request_certificate, returned in finalize
        self._cert_private_key = None

    # ── Account Management ────────────────────────────────────────

    def register_or_load(self) -> None:
        """Register a new ACME account or load an existing one.

        The account key (EC P-256) is persisted to ``account_key_path``
        so we can reuse the same registration across runs.
        """
        key_path = Path(self._config.account_key_path)
        key_path.parent.mkdir(parents=True, exist_ok=True)

        if key_path.exists():
            log.info("Loading existing ACME account key")
            private_key = serialization.load_pem_private_key(
                key_path.read_bytes(), password=None
            )
        else:
            log.info("Generating new ACME account key (EC P-256)")
            private_key = ec.generate_private_key(ec.SECP256R1())
            key_path.write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        self._account_key = jose.JWK.load(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        # Build ACME client from directory URL
        # EC P-256 keys require ES256 algorithm (default is RS256 for RSA)
        net = client.ClientNetwork(
            self._account_key, user_agent=_USER_AGENT, alg=jose.ES256
        )
        directory = messages.Directory.from_json(
            net.get(self._config.directory_url).json()
        )
        self._acme_client = client.ClientV2(directory, net=net)

        # Register or find existing account
        reg = messages.NewRegistration.from_data(
            email=self._config.email,
            terms_of_service_agreed=True,
        )
        try:
            self._acme_client.new_account(reg)
            log.info("ACME account registered")
        except acme_errors.ConflictError as e:
            # Account exists - load it via the Location URL from the error
            log.info("ACME account already exists, reusing")
            existing_regr = messages.RegistrationResource(
                uri=e.location,
                body=messages.Registration(),
            )
            self._acme_client.net.account = existing_regr
            self._acme_client.query_registration(existing_regr)

    # ── Certificate Issuance ──────────────────────────────────────

    def request_certificate(
        self, domain: str, *, san: list[str] | None = None
    ) -> tuple[messages.OrderResource, list[dict]]:
        """Create a new order and extract dns-01 challenge info.

        Generates a fresh RSA-2048 key + CSR for the certificate,
        creates the ACME order, and locates dns-01 challenges for
        every authorization (wildcard + SAN certs may have multiple).

        Args:
            domain: Primary FQDN (may be wildcard like ``*.example.com``).
            san: Optional list of Subject Alternative Names to include
                 alongside the primary domain.

        Returns:
            Tuple of (order, challenge_list).
            Each element in challenge_list is a dict with keys:
                - domain: identifier domain value
                - record_name: ``_acme-challenge.{base_domain}``
                - validation: TXT record value to set
                - challenge_body: ChallengeBody (pass to answer_challenge)
        """
        self._ensure_client()

        # Generate cert private key (RSA-2048)
        self._cert_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Build CSR with optional SAN extension
        all_domains = [domain] + (san or [])
        builder = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
            )
        )
        if len(all_domains) > 1:
            san_names = [x509.DNSName(d) for d in all_domains]
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_names),
                critical=False,
            )
        csr = builder.sign(self._cert_private_key, hashes.SHA256())
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)

        # Create ACME order (the library stores the CSR in OrderResource)
        order = self._acme_client.new_order(csr_pem)
        log.info(f"ACME order created for {domain}" + (f" + SAN {san}" if san else ""))

        # Locate dns-01 challenges (one per authorization)
        challenge_list = self._find_dns01_challenges(order)
        return order, challenge_list

    def answer_challenge(self, challenge_body: messages.ChallengeBody) -> None:
        """Notify the ACME server that the DNS record is in place.

        Args:
            challenge_body: From the ``challenge_info`` returned by
                ``request_certificate()``.
        """
        self._ensure_client()
        response = challenge_body.response(self._account_key)
        self._acme_client.answer_challenge(challenge_body, response)
        log.info("ACME challenge answered")

    def poll_and_finalize(
        self, order: messages.OrderResource, *, timeout: int = 300
    ) -> tuple[str, str]:
        """Wait for validation, finalize, and download the certificate.

        Uses the library's built-in ``poll_and_finalize`` which handles:
        1. Polling authorizations until all are valid
        2. Sending the CSR to finalize the order
        3. Downloading the issued certificate chain

        Args:
            order: OrderResource from ``request_certificate()``.
            timeout: Max seconds to wait for validation + issuance.

        Returns:
            Tuple of (fullchain_pem, private_key_pem).

        Raises:
            TimeoutError: If validation does not complete in time.
            RuntimeError: If the order becomes invalid.
        """
        self._ensure_client()
        if self._cert_private_key is None:
            raise RuntimeError("No cert key found. Call request_certificate() first.")

        # acme library uses naive local datetime internally (datetime.now()),
        # so we must pass a naive local deadline to match
        deadline = datetime.now() + timedelta(seconds=timeout)

        try:
            finalized = self._acme_client.poll_and_finalize(order, deadline=deadline)
        except acme_errors.TimeoutError:
            raise TimeoutError(
                f"ACME order did not complete within {timeout}s. "
                "DNS propagation may be slow - retry later."
            )
        except acme_errors.ValidationError as e:
            raise RuntimeError(
                f"ACME validation failed: {e!r}. Check DNS records."
            ) from e

        # Extract fullchain PEM
        fullchain_pem = finalized.fullchain_pem

        # Export cert private key as PEM
        private_key_pem = self._cert_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        # Clear the key reference (one-shot use)
        self._cert_private_key = None

        return fullchain_pem, private_key_pem

    # ── Account Utilities ────────────────────────────────────────

    def get_account_uri(self) -> str:
        """Return the current ACME account URI.

        Required for building dns-persist-01 records.

        Raises:
            RuntimeError: If the client has not been initialised.
        """
        self._ensure_client()
        account = self._acme_client.net.account
        if account is None or not account.uri:
            raise RuntimeError("ACME account not registered yet.")
        return account.uri

    # ── Unified Challenge Discovery ────────────────────────────

    def find_challenges(
        self,
        order: messages.OrderResource,
        preferred_type: str = "dns-01",
    ) -> list[dict]:
        """Locate challenges across all authorizations.

        If *preferred_type* is ``dns-persist-01``, each authorisation is
        first searched for that type.  If it is not offered, the method
        transparently falls back to ``dns-01`` for that authorisation.

        Args:
            order: OrderResource from ``request_certificate()``.
            preferred_type: ``"dns-01"`` or ``"dns-persist-01"``.

        Returns:
            List of challenge info dicts (one per authorization).
        """
        if preferred_type == "dns-01":
            return self._find_dns01_challenges(order)

        # Try dns-persist-01 first, then fall back to dns-01
        result: list[dict] = []
        for authz in order.authorizations:
            domain = authz.body.identifier.value
            base_domain = strip_wildcard(domain)

            found = self._find_persist_challenge_in_authz(authz, domain, base_domain)
            if found is None:
                found = self._find_dns01_challenge_in_authz(authz, domain, base_domain)
            if found is None:
                raise RuntimeError(
                    f"No dns-01 or dns-persist-01 challenge found for {domain}."
                )
            result.append(found)

        if not result:
            raise RuntimeError(
                "No challenges found in ACME order."
            )
        return result

    def answer_persist_challenge(self, challb) -> None:
        """Answer a dns-persist-01 challenge.

        For ``UnrecognizedChallenge`` the ``acme`` library cannot build
        a typed response, so we POST an empty JSON body directly to the
        challenge URL ourselves.
        """
        self._ensure_client()

        url = challb.uri if hasattr(challb, "uri") else challb.jobj.get("url")
        if not url:
            raise RuntimeError("Cannot determine challenge URL for persist challenge.")

        # Use the ACME client's signed POST (JWS) with empty payload
        self._acme_client.net.post(url, obj=b"{}")
        log.info("dns-persist-01 challenge answered")

    # ── Diagnostics ───────────────────────────────────────────────

    def check_connectivity(self) -> dict:
        """Test connectivity to the ACME directory server.

        Returns:
            dict with ``ok``, ``url``, and either ``endpoints`` or ``error``.
        """
        try:
            import urllib.request

            url = self._config.directory_url
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", _USER_AGENT)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                return {"ok": True, "url": url, "endpoints": list(data.keys())}
        except Exception as e:
            return {"ok": False, "url": self._config.directory_url, "error": str(e)}

    # ── Internal ──────────────────────────────────────────────────

    def _find_dns01_challenges(
        self, order: messages.OrderResource
    ) -> list[dict]:
        """Locate dns-01 challenges across all authorizations.

        Wildcard domains (``*.example.com``) get their ``*`` prefix stripped
        so the record name becomes ``_acme-challenge.example.com``.

        Returns:
            List of challenge info dicts (one per authorization).
        """
        result: list[dict] = []
        for authz in order.authorizations:
            domain = authz.body.identifier.value
            for challb in authz.body.challenges:
                if isinstance(challb.chall, challenges.DNS01):
                    validation = challb.chall.validation(self._account_key)
                    base_domain = strip_wildcard(domain)
                    result.append({
                        "domain": domain,
                        "record_name": f"_acme-challenge.{base_domain}",
                        "validation": validation,
                        "challenge_body": challb,
                    })
                    break  # one dns-01 per authorization is enough

        if not result:
            raise RuntimeError(
                "No dns-01 challenge found in ACME order. "
                "Server may not support DNS validation for this request."
            )
        return result

    def _find_dns01_challenge_in_authz(self, authz, domain: str, base_domain: str) -> dict | None:
        """Extract a single dns-01 challenge from one authorization."""
        for challb in authz.body.challenges:
            if isinstance(challb.chall, challenges.DNS01):
                validation = challb.chall.validation(self._account_key)
                return {
                    "_type": "dns-01",
                    "domain": domain,
                    "record_name": f"_acme-challenge.{base_domain}",
                    "validation": validation,
                    "challenge_body": challb,
                }
        return None

    def _find_persist_challenge_in_authz(self, authz, domain: str, base_domain: str) -> dict | None:
        """Extract a dns-persist-01 challenge (``UnrecognizedChallenge``) from one authorization."""
        for challb in authz.body.challenges:
            # dns-persist-01 arrives as UnrecognizedChallenge in current acme lib
            jobj = getattr(challb, "jobj", None) or (
                getattr(challb.chall, "jobj", None) if hasattr(challb, "chall") else None
            )
            if jobj and jobj.get("type") == "dns-persist-01":
                return {
                    "_type": "dns-persist-01",
                    "domain": domain,
                    "base_domain": base_domain,
                    "record_name": f"_acme-challenge.{base_domain}",
                    "challenge_body": challb,
                }
        return None

    def _ensure_client(self) -> None:
        """Ensure the ACME client has been initialized."""
        if self._acme_client is None:
            raise RuntimeError(
                "ACME client not initialized. Call register_or_load() first."
            )
