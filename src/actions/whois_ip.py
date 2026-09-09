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
import time

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import (
    ActionOutput,
    OutputField,
    PermissiveActionOutput,
)
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..helper import is_ip, lookup_ip, make_json_safe


logger = getLogger()


class WhoisIpParams(Params):
    ip: str = Param(
        description="IP to query",
        primary=True,
        cef_types=["ip", "ipv6"],
        column_name="IP",
    )


class NetworkOutput(PermissiveActionOutput):
    abuse_emails: str | None = OutputField(
        cef_types=["email"], column_name="Abuse Emails"
    )
    address: str | None = OutputField(
        example_values=["1600 AmphiLane Markway"], column_name="Address"
    )
    cidr: str | None = OutputField(
        example_values=["127.127.127.127/20"], column_name="CIDR"
    )
    city: str | None = OutputField(
        example_values=["San Franscisco"], column_name="City"
    )
    country: str | None = OutputField(example_values=["US"], column_name="Country")
    created: str | None = OutputField(column_name="Created")
    description: str | None = OutputField(
        example_values=["Level 3 Test, LLC"], column_name="Description"
    )
    emails: str | None = OutputField(
        cef_types=["email"],
        example_values=["ipaddressing@level3.com"],
        column_name="Emails",
    )
    handle: str | None = OutputField(example_values=["NET-8-8-8-0-1"])
    name: str | None = OutputField(
        example_values=["LVLT-GOGL-8-8-8"], column_name="Name"
    )
    postal_code: str | None = OutputField(
        example_values=["94043"], column_name="Postal Code"
    )
    range: str | None = OutputField(
        example_values=["127.127.127.127 - 127.127.143.255"],
        column_name="Range",
    )
    state: str | None = OutputField(example_values=["CA"], column_name="State")
    tech_emails: str | None = OutputField(
        cef_types=["email"], column_name="Tech Emails"
    )
    updated: str | None = OutputField(
        example_values=["2014-03-14"], column_name="Updated"
    )
    misc_emails: str | None = OutputField(
        cef_types=["email"], column_name="Misc Emails"
    )


class WhoisIpOutput(PermissiveActionOutput):
    asn: str | None = OutputField(example_values=["18207"], column_name="ASN")
    asn_cidr: str | None = OutputField(
        example_values=["127.127.127.127/24"], column_name="ASN CIDR"
    )
    asn_country_code: str | None = OutputField(
        example_values=["US"], column_name="ASN Country Code"
    )
    asn_date: str | None = OutputField(
        example_values=["2000-04-27"], column_name="ASN Date"
    )
    asn_description: str | None = None
    asn_registry: str | None = OutputField(
        example_values=["apnic"], column_name="ASN Registry"
    )
    nets: list[NetworkOutput] | None = None
    nir: str | None = None
    query: str | None = OutputField(
        cef_types=["ip", "ipv6"], example_values=["127.127.127.127"]
    )
    raw: str | None = None
    raw_referral: str | None = None
    referral: str | None = None


class WhoisIpSummaryNetwork(ActionOutput):
    address: str | None = None
    range: str | None = None


class WhoisIpSummary(ActionOutput):
    asn: str | None = OutputField(example_values=["18207"])
    country_code: str | None = OutputField(example_values=["US"])
    nets: list[WhoisIpSummaryNetwork] | None = None
    registry: str | None = OutputField(example_values=["apnic"])


def whois_ip(params: WhoisIpParams, soar: SOARClient, asset) -> WhoisIpOutput:
    """Execute a WHOIS lookup on an IPv4 or IPv6 address."""
    del asset
    if not is_ip(params.ip):
        raise ActionFailure("Please provide a valid IPV4 or IPV6 address")

    time.sleep(1)
    logger.debug("Validating/querying IP %r", params.ip)
    logger.progress("Querying...")
    response = make_json_safe(lookup_ip(params.ip))
    logger.progress("Parsing response")

    summary_values = {}
    message_parts = []
    if response.get("asn_registry") is not None:
        registry = str(response["asn_registry"])
        summary_values["registry"] = registry
        message_parts.append(f"Registry: {registry}")
    if response.get("asn") is not None:
        asn = str(response["asn"])
        summary_values["asn"] = asn
        message_parts.append(f"ASN: {asn}")
    if response.get("asn_country_code") is not None:
        country = str(response["asn_country_code"])
        summary_values["country_code"] = country
        message_parts.append(f"Country: {country}")

    summary_networks = []
    if response.get("nets"):
        message_parts.append("Nets:")
        for network in response["nets"]:
            summary_network = WhoisIpSummaryNetwork(
                range=(
                    str(network["range"]) if network.get("range") is not None else None
                ),
                address=(
                    str(network["address"])
                    if network.get("address") is not None
                    else None
                ),
            )
            summary_networks.append(summary_network)
            message_parts.append(f"Range: {summary_network.range}")
            message_parts.append(f"Address: {summary_network.address}")
        summary_values["nets"] = summary_networks

    soar.set_summary(WhoisIpSummary(**summary_values))
    soar.set_message("\n".join(message_parts))
    return WhoisIpOutput(**response)
