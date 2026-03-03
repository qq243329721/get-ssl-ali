"""Alibaba Cloud DNS resolution API client."""

from __future__ import annotations

from alibabacloud_alidns20150109 import client as dns_client_module
from alibabacloud_alidns20150109 import models as dns_models
from alibabacloud_tea_openapi import models as openapi_models

from ssl_manager.models import AliyunCredential
from ssl_manager.utils.logger import log


class DnsClient:
    """Wrapper for Alibaba Cloud DNS API."""

    def __init__(self, credential: AliyunCredential):
        config = openapi_models.Config(
            access_key_id=credential.access_key_id,
            access_key_secret=credential.access_key_secret,
            endpoint="alidns.cn-hangzhou.aliyuncs.com",
        )
        self._client = dns_client_module.Client(config)

    def add_record(
        self,
        domain: str,
        rr: str,
        record_type: str,
        value: str,
        ttl: int = 600,
    ) -> str:
        """Add a DNS record.

        Args:
            domain: Root domain (e.g. "example.com").
            rr: Host record (e.g. "_dnsauth" or "_acme-challenge").
            record_type: Record type (e.g. "TXT", "CNAME").
            value: Record value.
            ttl: TTL in seconds.

        Returns:
            record_id for later cleanup.
        """
        request = dns_models.AddDomainRecordRequest(
            domain_name=domain,
            rr=rr,
            type=record_type,
            value=value,
            ttl=ttl,
        )
        resp = self._client.add_domain_record(request)
        record_id = resp.body.record_id
        log.info(f"DNS record added: {rr}.{domain} {record_type} = {value} (id={record_id})")
        return record_id

    def delete_record(self, record_id: str) -> None:
        """Delete a DNS record by ID.

        Args:
            record_id: The record ID to delete.
        """
        request = dns_models.DeleteDomainRecordRequest(
            record_id=record_id,
        )
        self._client.delete_domain_record(request)
        log.info(f"DNS record deleted: id={record_id}")

    def find_records(
        self,
        domain: str,
        rr: str | None = None,
        record_type: str | None = None,
    ) -> list[dict]:
        """Find DNS records matching criteria.

        Args:
            domain: Root domain to search in.
            rr: Optional host record filter.
            record_type: Optional record type filter.

        Returns:
            List of matching record dicts.
        """
        request = dns_models.DescribeDomainRecordsRequest(
            domain_name=domain,
            rrkey_word=rr,
            type=record_type,
            page_number=1,
            page_size=500,
        )
        resp = self._client.describe_domain_records(request)
        body = resp.body

        records = []
        if body.domain_records and body.domain_records.record:
            for rec in body.domain_records.record:
                records.append({
                    "record_id": rec.record_id,
                    "rr": rec.rr,
                    "type": rec.type,
                    "value": rec.value,
                    "domain_name": rec.domain_name,
                    "ttl": rec.ttl,
                    "status": rec.status,
                })
        return records

    def cleanup_validation_records(
        self, domain: str, rr: str, record_type: str = "TXT"
    ) -> int:
        """Delete all DNS validation records matching criteria.

        Args:
            domain: Root domain.
            rr: Host record to match.
            record_type: Record type to match.

        Returns:
            Number of records deleted.
        """
        records = self.find_records(domain, rr=rr, record_type=record_type)
        count = 0
        for rec in records:
            if rec["rr"] == rr and rec["type"] == record_type:
                self.delete_record(rec["record_id"])
                count += 1
        if count > 0:
            log.info(f"Cleaned up {count} validation record(s) for {rr}.{domain}")
        return count
