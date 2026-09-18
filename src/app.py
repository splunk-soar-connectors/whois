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
from pydantic import field_validator
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.exceptions import ActionFailure, AssetMisconfiguration
from soar_sdk.logging import getLogger
from soar_sdk.networking import Host

from .actions.whois_domain import (
    WhoisDomainSummary,
    render_whois_domain,
    whois_domain,
)
from .actions.whois_ip import WhoisIpSummary, whois_ip
from .helper import fetch_whois_info, is_ip, lookup_ip


logger = getLogger()


class Asset(BaseAsset):
    update_days: int = AssetField(
        required=True,
        description="Update the tld list once every N days",
        default=14,
        category=FieldCategory.CONNECTIVITY,
    )
    # SDK 4.3's Host alias cannot currently be wrapped in Optional, so retain the
    # SDK's required=False compatibility behavior for this optional field.
    server: Host = AssetField(
        required=False,
        description="WHOIS server IP address or hostname",
        category=FieldCategory.CONNECTIVITY,
    )
    allow_public_fallback: bool = AssetField(
        required=False,
        description=(
            "Allow public WHOIS fallback when a configured server cannot be queried"
        ),
        default=False,
        category=FieldCategory.CONNECTIVITY,
    )
    test_connectivity_target: Host = AssetField(
        required=False,
        description="IP address or hostname queried by Test Connectivity",
        default="1.1.1.1",
        category=FieldCategory.CONNECTIVITY,
    )

    @field_validator("update_days")
    @classmethod
    def validate_update_days(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("update_days must be a non-zero positive integer")
        return value


app = App(
    name="WHOIS",
    app_type="information",
    logo="logo_splunk.svg",
    logo_dark="logo_splunk_dark.svg",
    product_vendor="Generic",
    product_name="Whois",
    publisher="Splunk",
    appid="e6723c2e-06ef-415a-8098-62c46c1cb71f",
    fips_compliant=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(asset: Asset) -> None:
    target = asset.test_connectivity_target

    if asset.server:
        logger.progress(
            "Querying configured WHOIS server '%s' for '%s'",
            asset.server,
            target,
        )
        try:
            fetch_whois_info(target, asset.server, False)
        except ActionFailure as configured_error:
            logger.warning(
                "Configured WHOIS server '%s' failed for '%s': %s",
                asset.server,
                target,
                configured_error.message,
            )
            if not asset.allow_public_fallback:
                raise AssetMisconfiguration(
                    configured_error.message
                ) from configured_error
            logger.progress(
                "Configured WHOIS server failed; querying public WHOIS for '%s'",
                target,
            )
        else:
            logger.info(
                "Test Connectivity passed using configured WHOIS server '%s' for '%s'",
                asset.server,
                target,
            )
            return
    else:
        logger.progress("Querying public WHOIS for '%s'", target)

    try:
        if is_ip(target):
            lookup_ip(target)
        else:
            fetch_whois_info(target, None, False)
    except ActionFailure as error:
        logger.error("Public WHOIS query failed for '%s': %s", target, error.message)
        raise AssetMisconfiguration(error.message) from error
    logger.info("Test Connectivity passed using public WHOIS for '%s'", target)


app.register_action(
    whois_domain,
    name="whois domain",
    description="Execute a whois lookup on the given domain",
    verbose=(
        "This action accepts URLs also. It will extract the domain name from the URL "
        "before making the action query. It also tries to strip out the subdomain if any."
    ),
    action_type="investigate",
    read_only=True,
    view_handler=render_whois_domain,
    view_template="whois_domain.html",
    summary_type=WhoisDomainSummary,
)

app.register_action(
    whois_ip,
    name="whois ip",
    description="Execute a whois lookup on the given IP",
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=WhoisIpSummary,
)


if __name__ == "__main__":
    app.cli()
