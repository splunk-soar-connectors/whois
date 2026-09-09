**Unreleased**

* Preserved parsed WHOIS contacts when raw records contain no-data marker text.
* Made fallback to public WHOIS servers configurable and disabled it by default.
* Stored the refreshed Public Suffix List in per-asset state instead of a shared filesystem cache.
* Updated the app to use tldextract 5.3.2 on Python 3.13 and 3.14.
* Converted the app to the Splunk SOAR SDK.
* Escaped context-menu values rendered by the WHOIS domain custom view.
* Rejected blank domain inputs, preserved legacy referral behavior, and classified IPv6 query results.
