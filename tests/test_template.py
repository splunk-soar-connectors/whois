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
import json
from pathlib import Path

from jinja2 import ChoiceLoader, DictLoader, Environment, FileSystemLoader


def test_whois_domain_template_renders_sdk_context():
    templates = Path(__file__).parent.parent / "templates"
    environment = Environment(
        loader=ChoiceLoader(
            [
                FileSystemLoader(templates),
                DictLoader(
                    {
                        "widgets/widget_template.html": (
                            "{% block widget_content %}{% endblock %}"
                        )
                    }
                ),
            ]
        ),
        autoescape=True,
    )
    environment.filters["to_json"] = json.dumps
    template = environment.get_template("whois_domain.html")

    rendered = template.render(
        container=42,
        results=[
            {
                "domain": "example.com",
                "message": "",
                "data": {
                    "contacts": {
                        "admin": {"email": "admin@example.com"},
                        "registrant": {"name": "Example"},
                    },
                    "raw": ["WHOIS data"],
                },
            }
        ],
    )

    assert 'class="whois"' in rendered
    assert "example.com" in rendered
    assert "admin@example.com" in rendered
    assert "WHOIS data" in rendered


def test_whois_domain_template_escapes_context_menu_values():
    templates = Path(__file__).parent.parent / "templates"
    environment = Environment(
        loader=ChoiceLoader(
            [
                FileSystemLoader(templates),
                DictLoader(
                    {
                        "widgets/widget_template.html": (
                            "{% block widget_content %}{% endblock %}"
                        )
                    }
                ),
            ]
        ),
        autoescape=True,
    )
    environment.filters["to_json"] = json.dumps
    template = environment.get_template("whois_domain.html")

    rendered = template.render(
        container=42,
        results=[
            {
                "domain": "example.com');alert(document.domain);//",
                "message": "",
                "data": {
                    "contacts": {
                        "admin": {"email": "x');alert(document.domain);//@example.com"},
                        "registrant": {
                            "email": "owner');alert(document.domain);//@example.com"
                        },
                    },
                    "raw": None,
                },
            }
        ],
    )

    assert "example.com');alert" not in rendered
    assert "x');alert" not in rendered
    assert "owner');alert" not in rendered
    assert "example.com&#39;);alert" in rendered
    assert "x&#39;);alert" in rendered
    assert "owner&#39;);alert" in rendered
