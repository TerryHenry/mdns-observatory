"""Fetch and validate the community-maintained DNS-SD service reference."""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.parse import urlparse
import json
import re

COMMUNITY_CATALOG_URL = "https://raw.githubusercontent.com/bbusse/mdns-discover/main/README.md"
COMMUNITY_CATALOG_SOURCE = "https://github.com/bbusse/mdns-discover"
SERVICE_TYPE_RE = re.compile(r"^_[a-z0-9-]+\._(?:tcp|udp)$", re.IGNORECASE)
MAX_README_BYTES = 2 * 1024 * 1024
MIN_VALID_ENTRIES = 100


def parse_community_catalog(markdown: str) -> list[dict]:
    """Read the upstream README service table; ignore malformed/non-service rows."""
    lines = str(markdown or "").splitlines()
    in_services = False
    entries = {}
    for line in lines:
        heading = line.strip()
        if heading.casefold() == "## services":
            in_services = True
            continue
        if in_services and heading.startswith("## "):
            break
        if not in_services or not heading.startswith("|"):
            continue
        cells = [cell.strip().replace("`", "") for cell in heading.strip("|").split("|")]
        if len(cells) < 2 or cells[0].casefold() in {"service type", "--------------"}:
            continue
        service_type = cells[0].strip().lower().rstrip(".")
        description = " ".join(cells[1:]).strip()
        if not SERVICE_TYPE_RE.fullmatch(service_type) or not description:
            continue
        description = re.sub(r"\s+", " ", description).strip()
        name = description.rstrip(". ") or service_type
        transport = service_type.rsplit("._", 1)[-1].upper()
        entries[service_type] = {
            "name": name[:120],
            "type": service_type,
            "transport": transport,
            "category": "Community",
            "description": (
                f"Community catalog description: {description} "
                "This reference may be incomplete or outdated; verify against vendor documentation "
                "and the observed SRV/TXT data before making network changes."
            ),
            "r1": "Community reference only; verify in your RUCKUS One tenant",
            "catalog_source": "bbusse/mdns-discover",
        }
    if len(entries) < MIN_VALID_ENTRIES:
        raise ValueError(f"Upstream catalog validation failed: found only {len(entries)} valid service entries")
    return sorted(entries.values(), key=lambda row: row["type"])


def fetch_community_catalog() -> dict:
    """Fetch README over HTTPS and return validated data plus update metadata."""
    request = Request(COMMUNITY_CATALOG_URL, headers={"User-Agent": "mDNS-Observatory/2.24", "Accept": "text/plain"})
    with urlopen(request, timeout=20) as response:
        final = urlparse(response.geturl())
        if final.scheme != "https" or final.hostname != "raw.githubusercontent.com":
            raise ValueError("The catalog update redirected to an unexpected host")
        body = response.read(MAX_README_BYTES + 1)
        last_modified = response.headers.get("Last-Modified", "")
    if len(body) > MAX_README_BYTES:
        raise ValueError("The upstream catalog is larger than the allowed download size")
    markdown = body.decode("utf-8")
    entries = parse_community_catalog(markdown)
    return {
        "source": COMMUNITY_CATALOG_SOURCE,
        "source_url": COMMUNITY_CATALOG_URL,
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "upstream_last_modified": last_modified,
        "entries": entries,
    }


def merge_service_catalogs(curated: list[dict], community: list[dict]) -> list[dict]:
    """Merge entries while preserving app-curated descriptions over upstream rows."""
    merged = {}
    for item in community or []:
        service_type = str(item.get("type") or "").strip().lower().rstrip(".")
        if SERVICE_TYPE_RE.fullmatch(service_type):
            merged[service_type] = dict(item, type=service_type)
    for item in curated or []:
        service_type = str(item.get("type") or "").strip().lower().rstrip(".")
        if SERVICE_TYPE_RE.fullmatch(service_type):
            merged[service_type] = dict(item, type=service_type)
    return sorted(merged.values(), key=lambda row: (row.get("category", "").casefold(), row["type"]))


def validate_cached_entries(value) -> list[dict]:
    """Validate persisted community entries before using them."""
    if not isinstance(value, list) or len(value) > 5000:
        raise ValueError("Saved community catalog has an invalid entry list")
    clean = {}
    for item in value:
        if not isinstance(item, dict):
            continue
        service_type = str(item.get("type") or "").strip().lower().rstrip(".")
        name = re.sub(r"\s+", " ", str(item.get("name") or "")).strip()
        description = re.sub(r"\s+", " ", str(item.get("description") or "")).strip()
        if not SERVICE_TYPE_RE.fullmatch(service_type) or not name or not description:
            continue
        clean[service_type] = {
            "name": name[:120], "type": service_type,
            "transport": "TCP" if service_type.endswith("._tcp") else "UDP",
            "category": "Community", "description": description[:1200],
            "r1": "Community reference only; verify in your RUCKUS One tenant",
            "catalog_source": "bbusse/mdns-discover",
        }
    if len(clean) < MIN_VALID_ENTRIES:
        raise ValueError("Saved community catalog did not contain enough valid service entries")
    return sorted(clean.values(), key=lambda row: row["type"])
