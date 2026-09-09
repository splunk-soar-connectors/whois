# Copyright (c) 2026 Splunk Inc.
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
import base64
import datetime
import gzip
from types import SimpleNamespace

import pytest
import requests
from soar_sdk.exceptions import ActionFailure

from src import helper
from src.consts import CACHE_DATA, CACHE_UPDATE_TIME, ISO_TIME_FORMAT


MINIMAL_SUFFIX_LIST = "// ===BEGIN ICANN DOMAINS===\ncom\nuk\nco.uk\n"


class FakeBackend:
    def __init__(self, state=None):
        self.state = state or {}

    def load_state(self):
        return dict(self.state)


class FakeCacheState:
    def __init__(self, current=None, legacy=None):
        self.current = current or {}
        self.backend = FakeBackend(legacy)
        self.saved = []

    def get_all(self):
        return dict(self.current)

    def put_all(self, value):
        self.current = dict(value)
        self.saved.append(dict(value))


def encoded_suffix_list(value=MINIMAL_SUFFIX_LIST):
    return base64.b64encode(gzip.compress(value.encode(), mtime=0)).decode()


def make_asset(current=None, legacy=None, update_days=14):
    return SimpleNamespace(
        cache_state=FakeCacheState(current=current, legacy=legacy),
        update_days=update_days,
    )


def test_get_domain_uses_fresh_state_without_fetching(monkeypatch):
    now = datetime.datetime.now(datetime.UTC).strftime(ISO_TIME_FORMAT)
    asset = make_asset(
        current={CACHE_DATA: encoded_suffix_list(), CACHE_UPDATE_TIME: now}
    )
    monkeypatch.setattr(
        helper,
        "_fetch_suffix_list",
        lambda: pytest.fail("fresh cache must not fetch"),
    )

    assert helper.get_domain("www.example.co.uk", asset) == "example.co.uk"
    assert asset.cache_state.saved == []


def test_failed_refresh_uses_stale_state_without_advancing_timestamp(monkeypatch):
    old_timestamp = "2000-01-01T00:00:00.000000Z"
    asset = make_asset(
        current={
            CACHE_DATA: encoded_suffix_list(),
            CACHE_UPDATE_TIME: old_timestamp,
        }
    )
    monkeypatch.setattr(
        helper,
        "_fetch_suffix_list",
        lambda: (_ for _ in ()).throw(RuntimeError("offline")),
    )

    assert helper.get_domain("www.example.com", asset) == "example.com"
    assert asset.cache_state.current[CACHE_UPDATE_TIME] == old_timestamp
    assert asset.cache_state.saved == []


def test_successful_refresh_persists_data_and_timestamp_together(monkeypatch):
    asset = make_asset()
    monkeypatch.setattr(helper, "_fetch_suffix_list", lambda: MINIMAL_SUFFIX_LIST)

    assert helper.get_domain("www.example.com", asset) == "example.com"
    assert len(asset.cache_state.saved) == 1
    assert (
        helper._load_cached_suffix_list(asset.cache_state.current)
        == MINIMAL_SUFFIX_LIST
    )
    assert CACHE_UPDATE_TIME in asset.cache_state.current


def test_suffix_list_refresh_honors_https_proxy(monkeypatch):
    observed_proxies = []

    def send(_session, request, **kwargs):
        observed_proxies.append(kwargs["proxies"])
        response = requests.Response()
        response.status_code = 200
        response._content = MINIMAL_SUFFIX_LIST.encode()
        response.request = request
        return response

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:8443")
    monkeypatch.setenv("https_proxy", "http://proxy.example:8443")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    monkeypatch.setattr(requests.Session, "send", send)

    assert helper._fetch_suffix_list() == MINIMAL_SUFFIX_LIST
    assert observed_proxies[0]["https"] == "http://proxy.example:8443"


def test_refresh_is_not_persisted_when_extraction_fails(monkeypatch):
    asset = make_asset()
    monkeypatch.setattr(helper, "_fetch_suffix_list", lambda: MINIMAL_SUFFIX_LIST)
    monkeypatch.setattr(
        helper,
        "_extract_with_suffix_list",
        lambda *_args: (_ for _ in ()).throw(ValueError("invalid list")),
    )

    with pytest.raises(ValueError, match="invalid list"):
        helper.get_domain("www.example.com", asset)
    assert asset.cache_state.saved == []


def test_flat_legacy_cache_state_is_migrated_once():
    legacy = {
        CACHE_DATA: encoded_suffix_list(),
        CACHE_UPDATE_TIME: "2000-01-01T00:00:00.000000Z",
        "app_version": "2.2.13",
    }
    asset = make_asset(legacy=legacy)

    migrated = helper._cache_state(asset)

    assert migrated == {
        CACHE_DATA: legacy[CACHE_DATA],
        CACHE_UPDATE_TIME: legacy[CACHE_UPDATE_TIME],
    }
    assert asset.cache_state.saved == [migrated]
    helper._cache_state(asset)
    assert asset.cache_state.saved == [migrated]


def fake_pythonwhois(raw_lookup, public_lookup):
    return SimpleNamespace(
        net=SimpleNamespace(get_whois_raw=raw_lookup, whois_request=None),
        parse=SimpleNamespace(
            registrant_regexes=[],
            admin_contact_regexes=[],
            tech_contact_regexes=[],
            billing_contact_regexes=[],
            parse_raw_whois=lambda raw: {"contacts": {}, "raw": raw},
        ),
        get_whois=public_lookup,
    )


def test_configured_server_failure_is_fail_closed(monkeypatch):
    public_calls = []

    def fail_raw(*_args):
        raise OSError("connection refused")

    def public_lookup(domain):
        public_calls.append(domain)

    module = fake_pythonwhois(fail_raw, public_lookup)
    monkeypatch.setattr(helper, "_pythonwhois_module", lambda: module)

    with pytest.raises(ActionFailure, match="configured WHOIS server"):
        helper.fetch_whois_info("example.com", "whois.internal", False)
    assert public_calls == []


def test_configured_server_can_explicitly_fall_back(monkeypatch):
    def fail_raw(*_args):
        raise OSError("connection refused")

    expected = {"contacts": {"registrant": {"name": "Example"}}}
    module = fake_pythonwhois(fail_raw, lambda _domain: expected)
    monkeypatch.setattr(helper, "_pythonwhois_module", lambda: module)

    assert helper.fetch_whois_info("example.com", "whois.internal", True) == expected


def test_parsed_contacts_override_raw_no_data_marker():
    response = {
        "contacts": {"registrant": {"name": "Example"}},
        "raw": ["Domain not found"],
    }
    assert helper.response_has_no_contact_data(response, "example.com") is False
