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
from soar_sdk.exceptions import ActionFailure

from src.app import Asset, app


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


def test_asset_uses_sdk_runtime_defaults_and_preserves_fallback_default():
    assert app.app_meta_info["python_version"] == PythonVersion.all_csv()
    assert app.app_meta_info["min_phantom_version"] == MIN_PHANTOM_VERSION
    asset = Asset(update_days=14)
    assert asset.server is None
    assert asset.allow_public_fallback is False

    with pytest.raises(ValidationError, match="non-zero positive integer"):
        Asset(update_days=0)


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
