# Author: TK
# Date: 11-06-2026
# Purpose: Enriches the IOCs list and prints it on the dashboard.

import json
import os
import time
from typing import Any

import requests

from config import BASE_DIR, ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY


CACHE_PATH = os.path.join(BASE_DIR, "data", "enrichment_cache.json")
CACHE_TTL_SECONDS = 24 * 60 * 60


class IOCEnricher:
    def __init__(self):
        self.cache = self._load_cache()


    def enrich_ip(self, ip: str) -> dict[str, Any]:
        cache_key = f"ip:{ip}"

        cached = self._get_cached(cache_key)

        if cached:
            return cached

        result = {
            "ip": ip,
            "abuseipdb": self._query_abuseipdb(ip),
            "virustotal": self._query_virustotal_ip(ip),
        }


        result["risk_score"] = self._calculate_risk(result)

        self._set_cached(cache_key, result)

        return result


    def _query_abuseipdb(self, ip: str) -> dict[str, Any]:
        if not ABUSEIPDB_API_KEY:
            return {
                "enabled": False,
                "error": "Missing ABUSEIPDB_API_KEY",
            }

        url = "https://api.abuseipdb.com/api/v2/check"

        headers = {
            "Key" : ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        }

        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90",
            "verbose": "true",
        }

        try:
            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=10,
            )

            response.raise_for_status()

            data = response.json().get("data", {})

            return {
                "enabled": True,
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "total_reports": data.get("totalReports", 0),
                "last_reported_at": data.get("lastReportedAt"),
            }

        except requests.RequestException as exc:
            return {
                "enabled": True,
                "error": str(exc),
            }

    def _query_virustotal_ip(self, ip: str) -> dict[str, Any]:
        if not VIRUSTOTAL_API_KEY:
            return {
                "enabled": False,
                "error": "Missing VIRUSTOTAL_API_KEY",
            }

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
        }

        try:
            response = requests.get(url, headers=headers, timeout=10)

            response.raise_for_status()

            attrs = response.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            return {
                "enabled": True,
                "country": attrs.get("country"),
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "reputation": attrs.get("reputation"),
                "malicious": attrs.get("malicious", 0),
                "suspicious": attrs.get("suspicious", 0),
                "harmless": attrs.get("harmless", 0),
            }

        except requests.RequestException as exc:
            return {
                "enabled": True,
                "error": str(exc),
            }

    @staticmethod
    def _calculate_risk(result: dict[str, Any]) -> int:
        abuse_score = (
            result.get("abuseipdb", {}).get("abuse_confidence_score", 0) or 0
        )

        vt = result.get("virustotal", {})


        vt_score = min(
            100,
            ((vt.get("malicious", 0) or 0) * 20)
            + ((vt.get("suspicious", 0) or 0) * 10),
        )

        return max(abuse_score, vt_score)


    def _load_cache(self) -> dict[str, Any]:
        if not os.path.exists(CACHE_PATH):
            return {}


        try:
            with open(CACHE_PATH, "r", encoding="utf-8") as file:
                return json.load(file)

        except (json.JSONDecodeError, OSError):
            return {}


    def _save_cache(self) -> None:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)

        with open(CACHE_PATH, "w", encoding="utf-8") as file:
            json.dump(self.cache, file, indent=2)


    def _get_cached(self, key: str):
        item = self.cache.get(key)

        if not item:
            return None

        if time.time() - item.get("cached_at", 0) > CACHE_TTL_SECONDS:
            return None

        return item.get("value")

    def _set_cached(self, key: str, value: dict[str, Any]) -> None:
        self.cache[key] = {
            "cached_at": time.time(),
            "value": value,
        }

        self._save_cache()

