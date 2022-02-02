[comment]: # "Auto-generated SOAR connector documentation"
# WHOIS

Publisher: Splunk  
Connector Version: 2\.1\.7  
Product Vendor: Generic  
Product Name: Whois  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

This app implements investigative actions that query the whois database

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
The app uses the tldextract python module while executing the 'whois domain' action. This module
uses the tld list from publicsuffix.org. The app ships with a tld list, however, it will try to
update the list the first time it runs and then tries to update it at a regular interval. The
interval is set in the app config.

This app will ignore the HTTP_PROXY and HTTPS_PROXY environment variables.

The user is requested to use CONFIGURE NEW ASSET option to configure a new asset.

## WHOIS Ports Requirements (Based on Standard Guidelines of [IANA ORG](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml) )

-   WHOIS(service) TCP(transport protocol) - 43
-   WHOIS(service) UDP(transport protocol) - 43

## ipwhois

This app uses the python-ipwhois module, which is licensed under the BSD License, Copyright (c)
2013-2019 Philip Hane.

## wizard-whois

This app uses the python wizard-whois module, which is licensed under the MIT License, Copyright (c)
Michael Ramsey.

## tldextract

This app uses the python tldextract module, which is licensed under the BSD License, Copyright (c)
John Kurkowski.

## dnspython

This app uses the python dnspython module, which is licensed under the ISC License, Copyright (c)
Bob Halley.

## requests-file

This app uses the python requests-file module, which is licensed under the Apache 2.0 License,
Copyright (c) David Shea.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Whois asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**update\_days** |  required  | numeric | Update the tld list once every N days

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the configuration for connectivity  
[whois domain](#action-whois-domain) - Execute a whois lookup on the given domain  
[whois ip](#action-whois-ip) - Execute a whois lookup on the given IP  

## action: 'test connectivity'
Validate the configuration for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'whois domain'
Execute a whois lookup on the given domain

Type: **investigate**  
Read only: **True**

This action accepts URLs also\. It will extract the domain name from the URL before making the action query\. It also tries to strip out the subdomain if any\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to query | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.data\.\*\.contacts\.admin | string | 
action\_result\.data\.\*\.contacts\.admin\.city | string | 
action\_result\.data\.\*\.contacts\.admin\.country | string | 
action\_result\.data\.\*\.contacts\.admin\.email | string |  `email` 
action\_result\.data\.\*\.contacts\.admin\.fax | string | 
action\_result\.data\.\*\.contacts\.admin\.name | string | 
action\_result\.data\.\*\.contacts\.admin\.organization | string | 
action\_result\.data\.\*\.contacts\.admin\.phone | string | 
action\_result\.data\.\*\.contacts\.admin\.postalcode | string | 
action\_result\.data\.\*\.contacts\.admin\.state | string | 
action\_result\.data\.\*\.contacts\.admin\.street | string | 
action\_result\.data\.\*\.contacts\.billing | string | 
action\_result\.data\.\*\.contacts\.registrant | string | 
action\_result\.data\.\*\.contacts\.registrant\.city | string | 
action\_result\.data\.\*\.contacts\.registrant\.country | string | 
action\_result\.data\.\*\.contacts\.registrant\.email | string |  `email` 
action\_result\.data\.\*\.contacts\.registrant\.fax | string | 
action\_result\.data\.\*\.contacts\.registrant\.name | string | 
action\_result\.data\.\*\.contacts\.registrant\.organization | string | 
action\_result\.data\.\*\.contacts\.registrant\.phone | string | 
action\_result\.data\.\*\.contacts\.registrant\.postalcode | string | 
action\_result\.data\.\*\.contacts\.registrant\.state | string | 
action\_result\.data\.\*\.contacts\.registrant\.street | string | 
action\_result\.data\.\*\.contacts\.tech | string | 
action\_result\.data\.\*\.contacts\.tech\.city | string | 
action\_result\.data\.\*\.contacts\.tech\.country | string | 
action\_result\.data\.\*\.contacts\.tech\.email | string |  `email` 
action\_result\.data\.\*\.contacts\.tech\.fax | string | 
action\_result\.data\.\*\.contacts\.tech\.name | string | 
action\_result\.data\.\*\.contacts\.tech\.organization | string | 
action\_result\.data\.\*\.contacts\.tech\.phone | string | 
action\_result\.data\.\*\.contacts\.tech\.postalcode | string | 
action\_result\.data\.\*\.contacts\.tech\.state | string | 
action\_result\.data\.\*\.contacts\.tech\.street | string | 
action\_result\.data\.\*\.creation\_date | string | 
action\_result\.data\.\*\.emails | string |  `email` 
action\_result\.data\.\*\.expiration\_date | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.nameservers | string | 
action\_result\.data\.\*\.raw | string | 
action\_result\.data\.\*\.registrar | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.updated\_date | string | 
action\_result\.data\.\*\.whois\_server | string | 
action\_result\.summary\.city | string | 
action\_result\.summary\.country | string | 
action\_result\.summary\.domain | string |  `domain`  `url` 
action\_result\.summary\.name | string | 
action\_result\.summary\.organization | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'whois ip'
Execute a whois lookup on the given IP

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.asn | string | 
action\_result\.data\.\*\.asn\_cidr | string | 
action\_result\.data\.\*\.asn\_country\_code | string | 
action\_result\.data\.\*\.asn\_date | string | 
action\_result\.data\.\*\.asn\_description | string | 
action\_result\.data\.\*\.asn\_registry | string | 
action\_result\.data\.\*\.nets\.\*\.abuse\_emails | string |  `email` 
action\_result\.data\.\*\.nets\.\*\.address | string | 
action\_result\.data\.\*\.nets\.\*\.cidr | string | 
action\_result\.data\.\*\.nets\.\*\.city | string | 
action\_result\.data\.\*\.nets\.\*\.country | string | 
action\_result\.data\.\*\.nets\.\*\.created | string | 
action\_result\.data\.\*\.nets\.\*\.description | string | 
action\_result\.data\.\*\.nets\.\*\.emails | string |  `email` 
action\_result\.data\.\*\.nets\.\*\.handle | string | 
action\_result\.data\.\*\.nets\.\*\.misc\_emails | string |  `email` 
action\_result\.data\.\*\.nets\.\*\.name | string | 
action\_result\.data\.\*\.nets\.\*\.postal\_code | string | 
action\_result\.data\.\*\.nets\.\*\.range | string | 
action\_result\.data\.\*\.nets\.\*\.state | string | 
action\_result\.data\.\*\.nets\.\*\.tech\_emails | string |  `email` 
action\_result\.data\.\*\.nets\.\*\.updated | string | 
action\_result\.data\.\*\.nir | string | 
action\_result\.data\.\*\.query | string |  `ip` 
action\_result\.data\.\*\.raw | string | 
action\_result\.data\.\*\.raw\_referral | string | 
action\_result\.data\.\*\.referral | string | 
action\_result\.summary\.asn | string | 
action\_result\.summary\.country\_code | string | 
action\_result\.summary\.nets\.\*\.address | string | 
action\_result\.summary\.nets\.\*\.range | string | 
action\_result\.summary\.registry | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 