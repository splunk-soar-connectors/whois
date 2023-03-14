[comment]: # "Auto-generated SOAR connector documentation"
# WHOIS

Publisher: Splunk  
Connector Version: 2\.2\.0  
Product Vendor: Generic  
Product Name: Whois  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.5\.0  

This app implements investigative actions that query the whois database

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2023 Splunk Inc."
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

## pythonwhois-alt

This app uses the pythonwhois module, which is licensed under the WTFPL License, Copyright (c) Yuriy
Zemskov.

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
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.domain | string |  `domain`  `url`  |   example\.com 
action\_result\.data\.\*\.contacts\.admin | string |  |   Test User 
action\_result\.data\.\*\.contacts\.admin\.city | string |  |  
action\_result\.data\.\*\.contacts\.admin\.country | string |  |  
action\_result\.data\.\*\.contacts\.admin\.email | string |  `email`  |  
action\_result\.data\.\*\.contacts\.admin\.fax | string |  |  
action\_result\.data\.\*\.contacts\.admin\.name | string |  |  
action\_result\.data\.\*\.contacts\.admin\.organization | string |  |  
action\_result\.data\.\*\.contacts\.admin\.phone | string |  |  
action\_result\.data\.\*\.contacts\.admin\.postalcode | string |  |  
action\_result\.data\.\*\.contacts\.admin\.state | string |  |  
action\_result\.data\.\*\.contacts\.admin\.street | string |  |  
action\_result\.data\.\*\.contacts\.billing | string |  |  
action\_result\.data\.\*\.contacts\.registrant | string |  |  
action\_result\.data\.\*\.contacts\.registrant\.city | string |  |  
action\_result\.data\.\*\.contacts\.registrant\.country | string |  |  
action\_result\.data\.\*\.contacts\.registrant\.email | string |  `email`  |  
action\_result\.data\.\*\.contacts\.registrant\.fax | string |  |  
action\_result\.data\.\*\.contacts\.registrant\.name | string |  |  
action\_result\.data\.\*\.contacts\.registrant\.organization | string |  |  
action\_result\.data\.\*\.contacts\.registrant\.phone | string |  |  
action\_result\.data\.\*\.contacts\.registrant\.postalcode | string |  |  
action\_result\.data\.\*\.contacts\.registrant\.state | string |  |  
action\_result\.data\.\*\.contacts\.registrant\.street | string |  |  
action\_result\.data\.\*\.contacts\.tech | string |  |  
action\_result\.data\.\*\.contacts\.tech\.city | string |  |  
action\_result\.data\.\*\.contacts\.tech\.country | string |  |  
action\_result\.data\.\*\.contacts\.tech\.email | string |  `email`  |  
action\_result\.data\.\*\.contacts\.tech\.fax | string |  |  
action\_result\.data\.\*\.contacts\.tech\.name | string |  |  
action\_result\.data\.\*\.contacts\.tech\.organization | string |  |  
action\_result\.data\.\*\.contacts\.tech\.phone | string |  |  
action\_result\.data\.\*\.contacts\.tech\.postalcode | string |  |  
action\_result\.data\.\*\.contacts\.tech\.state | string |  |  
action\_result\.data\.\*\.contacts\.tech\.street | string |  |  
action\_result\.data\.\*\.creation\_date | string |  |   1997\-09\-15T04\:00\:00 
action\_result\.data\.\*\.emails | string |  `email`  |   abusecomplaints\@testmonitor\.com 
action\_result\.data\.\*\.expiration\_date | string |  |   2020\-09\-14T04\:00\:00 
action\_result\.data\.\*\.id | string |  |   2138514\_DOMAIN\_COM\-VRSN 
action\_result\.data\.\*\.nameservers | string |  |   NS4\.EXAMPLE\.COM 
action\_result\.data\.\*\.raw | string |  |      Domain Name\: EXAMPLE\.COM
   Registry Domain ID\: 2138514\_DOMAIN\_COM\-VRSN
   Registrar WHOIS Server\: whois\.testmonitor\.com
   Registrar URL\: http\://www\.testmonitor\.com
   Updated Date\: 2018\-02\-21T18\:36\:40Z
   Creation Date\: 1997\-09\-15T04\:00\:00Z
   Registry Expiry Date\: 2020\-09\-14T04\:00\:00Z
   Registrar\: TestMonitor Inc\.
   Registrar IANA ID\: 292
   Registrar Abuse Contact Email\: abusecomplaints\@testmonitor\.com
   Registrar Abuse Contact Phone\: \+1\.2083895740
   Domain Status\: clientDeleteProhibited https\://icann\.org/epp\#clientDeleteProhibited
   Domain Status\: clientTransferProhibited https\://icann\.org/epp\#clientTransferProhibited
   Domain Status\: clientUpdateProhibited https\://icann\.org/epp\#clientUpdateProhibited
   Domain Status\: serverDeleteProhibited https\://icann\.org/epp\#serverDeleteProhibited
   Domain Status\: serverTransferProhibited https\://icann\.org/epp\#serverTransferProhibited
   Domain Status\: serverUpdateProhibited https\://icann\.org/epp\#serverUpdateProhibited
   Name Server\: NS1\.EXAMPLE\.COM
   Name Server\: NS2\.EXAMPLE\.COM
   Name Server\: NS3\.EXAMPLE\.COM
   Name Server\: NS4\.EXAMPLE\.COM
   DNSSEC\: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form\: https\://www\.icann\.org/wicf/
>>> Last update of whois database\: 2018\-11\-16T06\:11\:04Z <<<

For more information on Whois status codes, please visit https\://icann\.org/epp

NOTICE\: The expiration date displayed in this record is the date the
registrar's sponsorship of the domain name registration in the registry is
currently set to expire\. This date does not necessarily reflect the expiration
date of the domain name registrant's agreement with the sponsoring
registrar\.  Users may consult the sponsoring registrar's Whois database to
view the registrar's reported date of expiration for this registration\.

TERMS OF USE\: You are not authorized to access or query our Whois
database through the use of electronic processes that are high\-volume and
automated except as reasonably necessary to register domain names or
modify existing registrations; the Data in VeriSign Global Registry
Services' \("VeriSign"\) Whois database is provided by VeriSign for
information purposes only, and to assist persons in obtaining information
about or related to a domain name registration record\. VeriSign does not
guarantee its accuracy\. By submitting a Whois query, you agree to abide
by the following terms of use\: You agree that you may use this Data only
for lawful purposes and that under no circumstances will you use this Data
to\: \(1\) allow, enable, or otherwise support the transmission of mass
unsolicited, commercial advertising or solicitations via e\-mail, telephone,
or facsimile; or \(2\) enable high volume, automated, electronic processes
that apply to VeriSign \(or its computer systems\)\. The compilation,
repackaging, dissemination or other use of this Data is expressly
prohibited without the prior written consent of VeriSign\. You agree not to
use electronic processes that are automated and high\-volume to access or
query the Whois database except as reasonably necessary to register
domain names or modify existing registrations\. VeriSign reserves the right
to restrict your access to the Whois database in its sole discretion to ensure
operational stability\.  VeriSign may restrict or terminate your access to the
Whois database for failure to abide by these terms of use\. VeriSign
reserves the right to modify these terms at any time\.

The Registry database contains ONLY \.COM, \.NET, \.EDU domains and
Registrars\.
 
action\_result\.data\.\*\.registrar | string |  |   TestMonitor Inc\. 
action\_result\.data\.\*\.status | string |  |   serverUpdateProhibited https\://icann\.org/epp\#serverUpdateProhibited 
action\_result\.data\.\*\.updated\_date | string |  |   2018\-02\-21T18\:36\:40 
action\_result\.data\.\*\.whois\_server | string |  |   whois\.testmonitor\.com 
action\_result\.summary\.city | string |  |  
action\_result\.summary\.country | string |  |  
action\_result\.summary\.domain | string |  `domain`  `url`  |   example\.com 
action\_result\.summary\.name | string |  |  
action\_result\.summary\.organization | string |  |  
action\_result\.message | string |  |   Whois query did not return any information 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1   

## action: 'whois ip'
Execute a whois lookup on the given IP

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip`  `ipv6` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action\_result\.status | string |  |   success  failed 
action\_result\.parameter\.ip | string |  `ip`  `ipv6`  |   127\.127\.127\.127 
action\_result\.data\.\*\.asn | string |  |   18207 
action\_result\.data\.\*\.asn\_cidr | string |  |   127\.127\.127\.127/24 
action\_result\.data\.\*\.asn\_country\_code | string |  |   US 
action\_result\.data\.\*\.asn\_date | string |  |   2000\-04\-27 
action\_result\.data\.\*\.asn\_description | string |  |  
action\_result\.data\.\*\.asn\_registry | string |  |   apnic 
action\_result\.data\.\*\.nets\.\*\.abuse\_emails | string |  `email`  |  
action\_result\.data\.\*\.nets\.\*\.address | string |  |   1600 AmphiLane Markway 
action\_result\.data\.\*\.nets\.\*\.cidr | string |  |   127\.127\.127\.127/20 
action\_result\.data\.\*\.nets\.\*\.city | string |  |   San Franscisco 
action\_result\.data\.\*\.nets\.\*\.country | string |  |   US 
action\_result\.data\.\*\.nets\.\*\.created | string |  |  
action\_result\.data\.\*\.nets\.\*\.description | string |  |   Level 3 Test, LLC 
action\_result\.data\.\*\.nets\.\*\.emails | string |  `email`  |   ipaddressing\@level3\.com 
action\_result\.data\.\*\.nets\.\*\.handle | string |  |   NET\-8\-8\-8\-0\-1 
action\_result\.data\.\*\.nets\.\*\.misc\_emails | string |  `email`  |  
action\_result\.data\.\*\.nets\.\*\.name | string |  |   LVLT\-GOGL\-8\-8\-8 
action\_result\.data\.\*\.nets\.\*\.postal\_code | string |  |   94043 
action\_result\.data\.\*\.nets\.\*\.range | string |  |   127\.127\.127\.127 \- 127\.127\.143\.255 
action\_result\.data\.\*\.nets\.\*\.state | string |  |   CA 
action\_result\.data\.\*\.nets\.\*\.tech\_emails | string |  `email`  |  
action\_result\.data\.\*\.nets\.\*\.updated | string |  |   2014\-03\-14 
action\_result\.data\.\*\.nir | string |  |  
action\_result\.data\.\*\.query | string |  `ip`  |   127\.127\.127\.127 
action\_result\.data\.\*\.raw | string |  |  
action\_result\.data\.\*\.raw\_referral | string |  |  
action\_result\.data\.\*\.referral | string |  |  
action\_result\.summary\.asn | string |  |   18207 
action\_result\.summary\.country\_code | string |  |   US 
action\_result\.summary\.nets\.\*\.address | string |  |   100 Century DriveLinks 
action\_result\.summary\.nets\.\*\.range | string |  |   127\.127\.127\.127 \- 127\.127\.143\.255 
action\_result\.summary\.registry | string |  |   apnic 
action\_result\.message | string |  |   Registry\: arin ASN\: 15169 Country\: US Nets\: Range\: 8\.0\.0\.0 \- 8\.127\.255\.255 Address\: 100 Century DriveLinks Range\: None Address\: 1600 AmphiLane Markway 
summary\.total\_objects | numeric |  |   1 
summary\.total\_objects\_successful | numeric |  |   1 