"""Alibaba Cloud CAS (Certificate Authority Service) API client.

Read-only client for querying existing certificate records.
Certificate issuance is handled exclusively via ACME (Let's Encrypt).
"""

from __future__ import annotations

from alibabacloud_cas20200407 import client as cas_client_module
from alibabacloud_cas20200407 import models as cas_models
from alibabacloud_tea_openapi import models as openapi_models

from ssl_manager.models import AliyunCredential


class CasClient:
    """Read-only wrapper for Alibaba Cloud CAS certificate API.

    Only used for querying existing certificate records (e.g. checking
    expiry of previously issued CAS certificates). All new certificate
    issuance goes through ACME.
    """

    def __init__(self, credential: AliyunCredential):
        config = openapi_models.Config(
            access_key_id=credential.access_key_id,
            access_key_secret=credential.access_key_secret,
            endpoint="cas.aliyuncs.com",
        )
        self._client = cas_client_module.Client(config)

    def list_user_certificates(
        self, keyword: str | None = None, status: str | None = None
    ) -> list[dict]:
        """List user certificate orders (read-only query)."""
        request = cas_models.ListUserCertificateOrderRequest(
            keyword=keyword,
            status=status,
            current_page=1,
            show_size=100,
        )
        resp = self._client.list_user_certificate_order(request)
        body = resp.body

        orders = []
        cert_list = getattr(body, "certificate_order_list", None) or []
        for item in cert_list:
            orders.append({
                "order_id": getattr(item, "order_id", None),
                "domain": getattr(item, "domain", None),
                "status": getattr(item, "status", None),
                "cert_start_time": getattr(item, "cert_start_time", None),
                "cert_end_time": getattr(item, "cert_end_time", None),
                "certificate_id": getattr(item, "certificate_id", None),
                "instance_id": getattr(item, "instance_id", None),
                "product_name": getattr(item, "product_name", None),
            })
        return orders
