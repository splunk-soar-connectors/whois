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
import importlib
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from soar_sdk.compat import MIN_PHANTOM_VERSION, PythonVersion
from soar_sdk.exceptions import ActionFailure, AssetMisconfiguration

from src.app import Asset, app


app_module = importlib.import_module("src.app")
domain_action = importlib.import_module("src.actions.whois_domain")
ip_action = importlib.import_module("src.actions.whois_ip")


class FakeSoar:
    def __init__(self):
        self.message = None
        self.summary = None

    def set_message(self, message):
        self.message = message

    def set_summary(self, summary):
        self.summary = summary


def test_asset_uses_sdk_runtime_defaults_and_network_types():
    assert app.app_meta_info["python_version"] == PythonVersion.all_csv()
    assert app.app_meta_info["min_phantom_version"] == MIN_PHANTOM_VERSION
    asset = Asset(update_days=14)
    assert asset.server is None
    assert asset.allow_public_fallback is False
    assert asset.test_connectivity_target == "1.1.1.1"
    assert Asset(update_days=14, server=" WHOIS.EXAMPLE.COM. ").server == (
        "whois.example.com"
    )

    with pytest.raises(ValidationError, match="non-zero positive integer"):
        Asset(update_days=0)
    with pytest.raises(ValidationError, match="valid IP address or hostname"):
        Asset(update_days=14, server="https://whois.example.com")
    with pytest.raises(ValidationError, match="valid IP address or hostname"):
        Asset(update_days=14, test_connectivity_target="   ")


def test_connectivity_uses_configured_server_and_logs_success(monkeypatch):
    calls = []
    info_messages = []
    monkeypatch.setattr(
        app_module,
        "fetch_whois_info",
        lambda *args: calls.append(args) or {"raw": ["response"]},
    )
    monkeypatch.setattr(
        app_module.logger,
        "info",
        lambda message, *args: info_messages.append(message % args),
    )
    asset = Asset(
        update_days=14,
        server="whois.internal",
        test_connectivity_target="example.com",
    )

    app_module.test_connectivity.__wrapped__(asset)

    assert calls == [("example.com", "whois.internal", False)]
    assert info_messages == [
        (
            "Test Connectivity passed using configured WHOIS server "
            "'whois.internal' for 'example.com'"
        )
    ]


def test_connectivity_fails_closed_and_logs_configured_server_error(monkeypatch):
    warning_messages = []
    monkeypatch.setattr(
        app_module,
        "fetch_whois_info",
        lambda *_args: (_ for _ in ()).throw(ActionFailure("connection refused")),
    )
    monkeypatch.setattr(
        app_module,
        "lookup_ip",
        lambda _target: pytest.fail("public fallback must remain disabled"),
    )
    monkeypatch.setattr(
        app_module.logger,
        "warning",
        lambda message, *args: warning_messages.append(message % args),
    )
    asset = Asset(update_days=14, server="whois.internal")

    with pytest.raises(AssetMisconfiguration, match="connection refused"):
        app_module.test_connectivity.__wrapped__(asset)

    assert warning_messages == [
        (
            "Configured WHOIS server 'whois.internal' failed for '1.1.1.1': "
            "connection refused"
        )
    ]


def test_connectivity_honors_public_fallback_for_ip_target(monkeypatch):
    public_calls = []
    info_messages = []
    monkeypatch.setattr(
        app_module,
        "fetch_whois_info",
        lambda *_args: (_ for _ in ()).throw(ActionFailure("connection refused")),
    )
    monkeypatch.setattr(
        app_module,
        "lookup_ip",
        lambda target: public_calls.append(target) or {"query": target},
    )
    monkeypatch.setattr(
        app_module.logger,
        "info",
        lambda message, *args: info_messages.append(message % args),
    )
    asset = Asset(
        update_days=14,
        server="whois.internal",
        allow_public_fallback=True,
    )

    app_module.test_connectivity.__wrapped__(asset)

    assert public_calls == ["1.1.1.1"]
    assert info_messages == [
        "Test Connectivity passed using public WHOIS for '1.1.1.1'"
    ]


def test_domain_output_preserves_legacy_contact_parent_datapaths():
    datapaths = {
        field["data_path"]
        for field in domain_action.WhoisDomainOutput._to_json_schema()
    }

    assert "action_result.data.*.contacts.admin" in datapaths
    assert "action_result.data.*.contacts.admin.email" in datapaths
    assert "action_result.data.*.contacts.registrant" in datapaths
    assert "action_result.data.*.contacts.tech" in datapaths


def test_whois_domain_preserves_contacts_despite_raw_marker(monkeypatch):
    response = {
        "contacts": {
            "admin": None,
            "billing": None,
            "tech": None,
            "registrant": {
                "name": "Domain Admin",
                "organization": "Example Inc.",
                "city": "Example City",
                "country": "US",
            },
        },
        "raw": ["Domain not found"],
        "whois_server": ["whois.example"],
    }
    monkeypatch.setattr(domain_action.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        domain_action, "get_domain", lambda _value, _asset: "example.com"
    )
    monkeypatch.setattr(domain_action, "configure_pythonwhois", lambda: None)
    monkeypatch.setattr(domain_action, "fetch_whois_info", lambda *_args: response)
    soar = FakeSoar()
    asset = SimpleNamespace(server=None, allow_public_fallback=False)

    output = domain_action.whois_domain(
        domain_action.WhoisDomainParams(domain="https://www.example.com/path"),
        soar,
        asset,
    )

    assert soar.summary.domain == "example.com"
    assert soar.summary.name == "Domain Admin"
    assert soar.message == ""
    assert output.model_dump()["contacts"]["registrant"]["name"] == "Domain Admin"


def test_whois_domain_rejects_plain_ip():
    with pytest.raises(ActionFailure, match="failed validation"):
        domain_action.whois_domain(
            domain_action.WhoisDomainParams(domain="8.8.8.8"),
            FakeSoar(),
            SimpleNamespace(server=None, allow_public_fallback=False),
        )


@pytest.mark.parametrize("domain", ["", "   "])
def test_whois_domain_params_reject_blank_values(domain):
    with pytest.raises(ValidationError, match="Please provide a domain or URL"):
        domain_action.WhoisDomainParams(domain=domain)


def test_whois_domain_does_not_follow_referral_without_contacts(monkeypatch):
    calls = []
    response = {"whois_server": ["whois.referral.example"], "raw": ["no data"]}
    monkeypatch.setattr(domain_action.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        domain_action, "get_domain", lambda _value, _asset: "example.com"
    )
    monkeypatch.setattr(domain_action, "configure_pythonwhois", lambda: None)
    monkeypatch.setattr(
        domain_action,
        "fetch_whois_info",
        lambda *args: calls.append(args) or response,
    )

    domain_action.whois_domain(
        domain_action.WhoisDomainParams(domain="example.com"),
        FakeSoar(),
        SimpleNamespace(server=None, allow_public_fallback=False),
    )

    assert calls == [("example.com", None, False)]


def test_whois_domain_follows_referral_when_contacts_lack_registrant(monkeypatch):
    calls = []
    responses = iter(
        [
            {
                "contacts": {"admin": {"name": "Admin"}},
                "whois_server": ["whois.referral.example"],
            },
            {"contacts": {"registrant": {"name": "Registrant"}}},
        ]
    )
    monkeypatch.setattr(domain_action.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        domain_action, "get_domain", lambda _value, _asset: "example.com"
    )
    monkeypatch.setattr(domain_action, "configure_pythonwhois", lambda: None)
    monkeypatch.setattr(
        domain_action,
        "fetch_whois_info",
        lambda *args: calls.append(args) or next(responses),
    )

    domain_action.whois_domain(
        domain_action.WhoisDomainParams(domain="example.com"),
        FakeSoar(),
        SimpleNamespace(server=None, allow_public_fallback=False),
    )

    assert calls == [
        ("example.com", None, False),
        ("example.com", "whois.referral.example", False),
    ]


def test_whois_ip_output_query_supports_ipv4_and_ipv6_cef_types():
    query_field = next(
        field
        for field in ip_action.WhoisIpOutput._to_json_schema()
        if field["data_path"] == "action_result.data.*.query"
    )

    assert query_field["contains"] == ["ip", "ipv6"]


def test_whois_ip_preserves_response_and_summary(monkeypatch):
    response = {
        "asn": "18207",
        "asn_cidr": "203.88.139.0/24",
        "asn_country_code": "IN",
        "asn_date": "2000-04-27",
        "asn_registry": "apnic",
        "nets": [{"range": "203.88.139.0 - 203.88.139.255", "address": "Test"}],
        "query": "203.88.139.34",
    }
    monkeypatch.setattr(ip_action.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(ip_action, "lookup_ip", lambda _ip: response)
    soar = FakeSoar()

    output = ip_action.whois_ip(
        ip_action.WhoisIpParams(ip="203.88.139.34"),
        soar,
        SimpleNamespace(),
    )

    assert output.model_dump() == response
    assert soar.summary.registry == "apnic"
    assert soar.summary.asn == "18207"
    assert soar.summary.country_code == "IN"
    assert "Range: 203.88.139.0 - 203.88.139.255" in soar.message


def test_whois_ip_rejects_non_ip():
    with pytest.raises(ActionFailure, match="valid IPV4 or IPV6"):
        ip_action.whois_ip(
            ip_action.WhoisIpParams(ip="example.com"),
            FakeSoar(),
            SimpleNamespace(),
        )
