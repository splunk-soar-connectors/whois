**Unreleased**

* Preserved parsed WHOIS contacts when raw records contain no-data marker text.
* Failed closed when a configured WHOIS server cannot be queried instead of using public fallback servers.
* Persisted fetched Public Suffix List data between WHOIS domain actions.
* Updated the app to use tldextract 5.3.2 on Python 3.13.
