# Copyright (c) 2016-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import annotations

import base64
import datetime
import gzip
import ipaddress
import json
import pkgutil
import socket
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

from .consts import (
    ADMIN_CONTACT_REGEXES,
    BILLING_CONTACT_REGEXES,
    CACHE_DATA,
    CACHE_UPDATE_TIME,
    ISO_TIME_FORMAT,
    REGISTRANT_REGEXES,
    TECH_CONTACT_REGEXES,
    TLD_LIST_MAX_BYTES,
    TLD_LIST_REQUEST_TIMEOUT_SECONDS,
    TLD_LIST_URLS,
    WHOIS_ERROR_QUERY,
    WHOIS_ERROR_QUERY_RETURNED_NO_DATA,
    WHOIS_MAX_RESPONSE_BYTES,
    WHOIS_SOCKET_TIMEOUT_SECONDS,
)

if TYPE_CHECKING:
    from .app import Asset


logger = getLogger()


def error_message_from_exception(error: Exception) -> str:
    """Return the legacy connector's compact exception message format."""
    error_code = None
    error_message: object = "Error message unavailable. Please check the asset configuration and|or action parameters"

    if len(error.args) > 1:
        error_code = error.args[0]
        error_message = error.args[1]
    elif len(error.args) == 1:
        error_message = error.args[0]

    if error_code:
        return f"Error Code: {error_code}. Error Message: {error_message}"
    return f"Error Message: {error_message}"


def is_ip(value: object) -> bool:
    """Return whether a value is an IPv4 or IPv6 literal."""
    try:
        ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return True


def _json_fallback(value: object) -> str:
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def make_json_safe(value: Any) -> Any:
    """Serialize datetime values and preserve embedded NULs as escaped text."""
    serialized = json.dumps(value, default=_json_fallback)
    return json.loads(serialized.replace("\\u0000", "\\\\u0000"))


def monkey_patched_whois_request(domain: str, server: str, port: int = 43) -> str:
    """Read a bounded WHOIS response while tolerating non-UTF-8 registries."""
    from charset_normalizer import detect  # noqa: PLC0415

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(WHOIS_SOCKET_TIMEOUT_SECONDS)
        sock.connect((server, port))
        sock.sendall(f"{domain}\r\n".encode())
        response = bytearray()
        while len(response) < WHOIS_MAX_RESPONSE_BYTES:
            data = sock.recv(min(1024, WHOIS_MAX_RESPONSE_BYTES - len(response)))
            if not data:
                break
            response.extend(data)
        if len(response) == WHOIS_MAX_RESPONSE_BYTES:
            raise ValueError(
                f"WHOIS response exceeds {WHOIS_MAX_RESPONSE_BYTES} byte limit"
            )
    finally:
        sock.close()

    encoding = detect(bytes(response)).get("encoding") or "utf-8"
    return bytes(response).decode(encoding)


def _pythonwhois_module() -> Any:
    import pythonwhois  # noqa: PLC0415

    return pythonwhois


def configure_pythonwhois() -> Any:
    """Apply the connector's parser additions and bounded socket implementation."""
    pythonwhois = _pythonwhois_module()
    pythonwhois.net.whois_request = monkey_patched_whois_request

    regex_groups = (
        (pythonwhois.parse.registrant_regexes, REGISTRANT_REGEXES),
        (pythonwhois.parse.admin_contact_regexes, ADMIN_CONTACT_REGEXES),
        (pythonwhois.parse.tech_contact_regexes, TECH_CONTACT_REGEXES),
        (pythonwhois.parse.billing_contact_regexes, BILLING_CONTACT_REGEXES),
    )
    for target, additions in regex_groups:
        for regex in additions:
            if regex not in target:
                target.append(regex)
    return pythonwhois


def lookup_ip(ip: str) -> dict[str, Any]:
    """Query IP WHOIS with the connector's KRNIC endpoint correction."""
    from ipwhois import IPDefinedError, IPWhois  # noqa: PLC0415
    from ipwhois.nir import NIR_WHOIS  # noqa: PLC0415

    NIR_WHOIS["krnic"]["url"] = "https://whois.kr/eng/whois.jsc"
    try:
        response = IPWhois(ip).lookup_whois(asn_methods=["whois", "dns", "http"])
    except IPDefinedError as error:
        raise ActionFailure(error_message_from_exception(error)) from error
    except Exception as error:
        detail = error_message_from_exception(error)
        raise ActionFailure(f"{WHOIS_ERROR_QUERY}: {detail}") from error

    if not response:
        raise ActionFailure(WHOIS_ERROR_QUERY_RETURNED_NO_DATA)
    return response


def _cache_state(asset: Asset) -> dict[str, Any]:
    """Load SDK cache state, migrating this PR's flat BaseConnector state once."""
    current = dict(asset.cache_state.get_all())
    if CACHE_DATA in current or CACHE_UPDATE_TIME in current:
        return current

    try:
        legacy = asset.cache_state.backend.load_state() or {}
    except Exception as error:
        logger.warning("Unable to inspect legacy WHOIS cache state: %s", error)
        return current

    migrated = {
        key: legacy[key]
        for key in (CACHE_DATA, CACHE_UPDATE_TIME)
        if legacy.get(key) is not None
    }
    if migrated:
        current.update(migrated)
        asset.cache_state.put_all(current)
    return current


def _should_update_cache(
    state: dict[str, Any], update_days: int, now: datetime.datetime | None = None
) -> bool:
    if not state.get(CACHE_DATA):
        return True
    if not (last_updated := state.get(CACHE_UPDATE_TIME)):
        return True

    try:
        updated_at = datetime.datetime.strptime(
            str(last_updated), ISO_TIME_FORMAT
        ).replace(tzinfo=datetime.UTC)
    except ValueError:
        return True

    current_time = now or datetime.datetime.now(datetime.UTC)
    return (current_time - updated_at).days >= update_days


def _load_cached_suffix_list(state: dict[str, Any]) -> str | None:
    if not (encoded_suffix_list := state.get(CACHE_DATA)):
        return None

    try:
        compressed_suffix_list = base64.b64decode(encoded_suffix_list, validate=True)
        suffix_list = gzip.decompress(compressed_suffix_list).decode("utf-8")
    except (TypeError, ValueError, OSError, UnicodeDecodeError) as error:
        logger.debug("Unable to load cached Public Suffix List: %s", error)
        return None

    suffix_list_bytes = suffix_list.encode("utf-8")
    if not suffix_list or len(suffix_list_bytes) > TLD_LIST_MAX_BYTES:
        return None
    return suffix_list


def _fetch_suffix_list() -> str:
    import requests  # noqa: PLC0415

    for url in TLD_LIST_URLS:
        try:
            response = requests.get(url, timeout=TLD_LIST_REQUEST_TIMEOUT_SECONDS)
            response.raise_for_status()
            if len(response.content) > TLD_LIST_MAX_BYTES:
                raise ValueError("Public Suffix List exceeds the size limit")
            return response.content.decode("utf-8")
        except Exception as error:
            logger.debug(
                "Unable to fetch the Public Suffix List from %s: %s", url, error
            )
    raise RuntimeError(
        "Unable to fetch the Public Suffix List from all configured URLs"
    )


def _get_bundled_suffix_list() -> str:
    suffix_list = pkgutil.get_data("tldextract", ".tld_set_snapshot")
    if suffix_list is None:
        raise RuntimeError("The tldextract Public Suffix List snapshot is unavailable")
    return suffix_list.decode("utf-8")


def _extract_with_suffix_list(hostname: str, suffix_list: str) -> Any:
    import tldextract  # noqa: PLC0415

    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".dat"
    ) as suffix_file:
        suffix_file.write(suffix_list)
        suffix_file.flush()
        extract = tldextract.TLDExtract(
            cache_dir=None,
            suffix_list_urls=(Path(suffix_file.name).resolve().as_uri(),),
            fallback_to_snapshot=False,
        )
        return extract(hostname)


def _store_suffix_list(asset: Asset, state: dict[str, Any], suffix_list: str) -> None:
    compressed = gzip.compress(suffix_list.encode("utf-8"), mtime=0)
    updated_state = dict(state)
    updated_state[CACHE_DATA] = base64.b64encode(compressed).decode("ascii")
    updated_state[CACHE_UPDATE_TIME] = datetime.datetime.now(datetime.UTC).strftime(
        ISO_TIME_FORMAT
    )
    asset.cache_state.put_all(updated_state)


def get_domain(hostname: str, asset: Asset) -> str:
    """Reduce a URL or hostname to its registrable domain using fresh PSL data."""
    state = _cache_state(asset)
    cached_suffix_list = _load_cached_suffix_list(state)
    should_update = _should_update_cache(state, asset.update_days)
    persist_suffix_list = False

    if should_update or cached_suffix_list is None:
        try:
            suffix_list = _fetch_suffix_list()
            persist_suffix_list = True
        except Exception as error:
            logger.debug("Unable to refresh the Public Suffix List: %s", error)
            suffix_list = cached_suffix_list or _get_bundled_suffix_list()
            persist_suffix_list = cached_suffix_list is None
    else:
        suffix_list = cached_suffix_list

    result = _extract_with_suffix_list(hostname, suffix_list)
    if persist_suffix_list:
        _store_suffix_list(asset, state, suffix_list)

    if result.suffix and result.domain:
        return f"{result.domain}.{result.suffix}"
    return result.suffix or result.domain or ""


def _server_hostname(server: str) -> str:
    parsed = urlparse(server)
    if parsed.scheme and parsed.netloc:
        if not parsed.hostname:
            raise ActionFailure(f"Configured WHOIS server URL is invalid: {server}")
        return parsed.hostname
    return server


def fetch_whois_info(
    domain: str, server: str | None, allow_public_fallback: bool
) -> dict[str, Any]:
    """Query a configured WHOIS server or the library's public discovery path."""
    pythonwhois = configure_pythonwhois()
    try:
        if server:
            server_hostname = _server_hostname(server)
            try:
                raw_response = pythonwhois.net.get_whois_raw(domain, server_hostname)
            except Exception as error:
                detail = error_message_from_exception(error)
                if not allow_public_fallback:
                    raise ActionFailure(
                        f"Failed to query the configured WHOIS server "
                        f"'{server_hostname}': {detail}"
                    ) from error
                logger.debug(
                    "Configured WHOIS server failed; trying public WHOIS fallback"
                )
                response = pythonwhois.get_whois(domain)
            else:
                response = pythonwhois.parse.parse_raw_whois(raw_response)
        else:
            response = pythonwhois.get_whois(domain)
    except ActionFailure:
        raise
    except Exception as error:
        detail = error_message_from_exception(error)
        raise ActionFailure(f"{WHOIS_ERROR_QUERY}: {detail}") from error

    if not response:
        raise ActionFailure(WHOIS_ERROR_QUERY_RETURNED_NO_DATA)
    return response


def response_has_no_contact_data(response: dict[str, Any], domain: str) -> bool:
    """Keep parsed contacts even when an untrusted raw line says no data."""
    contacts = response.get("contacts") or {}
    if any(
        contacts.get(contact_type)
        for contact_type in ("admin", "tech", "registrant", "billing")
    ):
        return False

    raw_response = response.get("raw") or []
    if isinstance(raw_response, str):
        raw_response = [raw_response]
    for line in raw_response:
        lowered = str(line).lower()
        if (
            "domain not found" in lowered
            or f"no match for '{domain}'".lower() in lowered
        ):
            return True
    return True


def first_whois_server(response: dict[str, Any]) -> str | None:
    servers = response.get("whois_server")
    if isinstance(servers, str):
        return servers or None
    if isinstance(servers, list) and servers:
        return str(servers[0]) if servers[0] else None
    return None
