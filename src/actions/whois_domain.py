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
import itertools
import time
from collections.abc import Iterator

from pydantic import field_validator
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import (
    ActionOutput,
    OutputField,
    OutputFieldSpecification,
    PermissiveActionOutput,
)
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..consts import (
    WHOIS_ERROR_QUERY_RETURNED_NO_CONTACTS_DATA,
    WHOIS_NO_SECONDARY_API,
    WHOIS_SUCC_QUERY,
    WHOIS_SUCC_QUERY_RETURNED_NO_REGISTRANT_DATA,
)
from ..helper import (
    configure_pythonwhois,
    error_message_from_exception,
    fetch_whois_info,
    first_whois_server,
    get_domain,
    is_ip,
    make_json_safe,
    response_has_no_contact_data,
)


logger = getLogger()


class WhoisDomainParams(Params):
    domain: str = Param(
        description="Domain to query",
        primary=True,
        cef_types=["domain", "url"],
    )

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Please provide a domain or URL")
        return value


class ContactOutput(PermissiveActionOutput):
    city: str | None = None
    country: str | None = None
    email: str | None = OutputField(cef_types=["email"])
    fax: str | None = None
    name: str | None = None
    organization: str | None = None
    phone: str | None = None
    postalcode: str | None = None
    state: str | None = None
    street: str | None = None


class ContactsOutput(PermissiveActionOutput):
    admin: ContactOutput | None = None
    billing: str | None = None
    registrant: ContactOutput | None = None
    tech: ContactOutput | None = None

    @classmethod
    def _to_json_schema(
        cls,
        parent_datapath: str = "action_result.data.*",
        column_order_counter: itertools.count | None = None,
    ) -> Iterator[OutputFieldSpecification]:
        """Preserve legacy parent datapaths alongside their nested contact fields."""
        if column_order_counter is None:
            column_order_counter = itertools.count()

        for field_name in ("admin", "billing", "registrant", "tech"):
            datapath = f"{parent_datapath}.{field_name}"
            yield OutputFieldSpecification(data_path=datapath, data_type="string")
            if field_name != "billing":
                yield from ContactOutput._to_json_schema(
                    datapath,
                    column_order_counter,
                )


class WhoisDomainOutput(PermissiveActionOutput):
    contacts: ContactsOutput | None = None
    creation_date: str | None = OutputField(example_values=["1997-09-15T04:00:00"])
    emails: str | None = OutputField(
        cef_types=["email"],
        example_values=["abusecomplaints@testmonitor.com"],
    )
    expiration_date: str | None = OutputField(example_values=["2020-09-14T04:00:00"])
    id: str | None = OutputField(example_values=["2138514_DOMAIN_COM-VRSN"])
    nameservers: str | None = OutputField(example_values=["NS4.EXAMPLE.COM"])
    raw: str | None = None
    registrar: str | None = OutputField(example_values=["TestMonitor Inc."])
    status: str | None = OutputField(
        example_values=[
            "serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited"
        ]
    )
    updated_date: str | None = OutputField(example_values=["2018-02-21T18:36:40"])
    whois_server: str | None = OutputField(example_values=["whois.testmonitor.com"])
    queried_domain: str | None = OutputField(cef_types=["domain", "url"])
    status_message: str | None = None


class WhoisDomainSummary(ActionOutput):
    domain: str = OutputField(
        cef_types=["domain", "url"], example_values=["example.com"]
    )
    city: str | None = None
    country: str | None = None
    name: str | None = None
    organization: str | None = None


def render_whois_domain(outputs: list[WhoisDomainOutput]) -> dict:
    return {
        "results": [
            {
                "data": output.model_dump(by_alias=True),
                "domain": output.queried_domain,
                "message": output.status_message,
            }
            for output in outputs
        ]
    }


def whois_domain(
    params: WhoisDomainParams, soar: SOARClient, asset
) -> WhoisDomainOutput:
    """Execute a WHOIS lookup on a URL or domain."""
    if is_ip(params.domain):
        raise ActionFailure("Parameter 'domain' failed validation")

    time.sleep(1)
    try:
        domain = get_domain(params.domain, asset)
    except Exception as error:
        detail = error_message_from_exception(error)
        raise ActionFailure(f"Unable to parse input data: {detail}") from error

    logger.debug("Validating/querying domain %r", domain)
    logger.progress("Querying...")
    configure_pythonwhois()

    response = fetch_whois_info(
        domain,
        asset.server,
        asset.allow_public_fallback,
    )
    contacts = response.get("contacts")
    if contacts and not contacts.get("registrant"):
        if secondary_server := first_whois_server(response):
            response = fetch_whois_info(
                domain,
                secondary_server,
                asset.allow_public_fallback,
            )
        else:
            logger.debug(WHOIS_NO_SECONDARY_API)

    logger.progress("Parsing response")
    try:
        response = make_json_safe(response)
    except Exception as error:
        detail = error_message_from_exception(error)
        raise ActionFailure(f"Unable to parse whois response: {detail}") from error

    summary_values = {"domain": domain}
    if response_has_no_contact_data(response, domain):
        message = (
            f"{WHOIS_SUCC_QUERY}, but, {WHOIS_ERROR_QUERY_RETURNED_NO_CONTACTS_DATA}."
        )
    elif registrant := (response.get("contacts") or {}).get("registrant"):
        for key in ("organization", "name", "city", "country"):
            if registrant.get(key) is not None:
                summary_values[key] = str(registrant[key]).replace("\x00", "\\u0000")
        message = ""
    else:
        message = (
            f"{WHOIS_SUCC_QUERY}, but, {WHOIS_SUCC_QUERY_RETURNED_NO_REGISTRANT_DATA}."
        )

    soar.set_summary(WhoisDomainSummary(**summary_values))
    soar.set_message(message)
    response["queried_domain"] = domain
    response["status_message"] = message
    return WhoisDomainOutput(**response)
