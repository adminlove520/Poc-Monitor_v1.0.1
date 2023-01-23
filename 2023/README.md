# 2023 List

---
## CVE-2023-24070 (2023-01-23T05:15:00)
> app/View/AuthKeys/authkey_display.ctp in MISP through 2.4.167 has an XSS in authkey add via a Referer field.
- [Live-Hack-CVE/CVE-2023-24070](https://github.com/Live-Hack-CVE/CVE-2023-24070)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24070">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24070">

---
## CVE-2023-24069 (2023-01-23T07:15:00)
> Signal Desktop before 6.2.0 on Windows, Linux, and macOS allows an attacker to obtain potentially sensitive attachments sent in messages from the attachments.noindex directory. Cached attachments are not effectively cleared. In some cases, even after a self-initiated file deletion, an attacker can still recover the file if it was previously replied to in a conversation. (Local filesystem access is needed by the attacker.)
- [Live-Hack-CVE/CVE-2023-24069](https://github.com/Live-Hack-CVE/CVE-2023-24069)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24069">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24069">

---
## CVE-2023-24068 (2023-01-23T07:15:00)
> Signal Desktop before 6.2.0 on Windows, Linux, and macOS allows an attacker to modify conversation attachments within the attachments.noindex directory. Client mechanisms fail to validate modifications of existing cached files, resulting in an attacker's ability to insert malicious code into pre-existing attachments or replace them completely. A threat actor can forward the existing attachment in the corresponding conversation to external groups, and the name and size of the file will not change, allowing the malware to masquerade as another file.
- [Live-Hack-CVE/CVE-2023-24068](https://github.com/Live-Hack-CVE/CVE-2023-24068)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24068">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24068">

---
## CVE-2023-24059 (2023-01-22T07:15:00)
> Grand Theft Auto V for PC allows attackers to achieve partial remote code execution or modify files on a PC, as exploited in the wild in January 2023.
- [Live-Hack-CVE/CVE-2023-24059](https://github.com/Live-Hack-CVE/CVE-2023-24059)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24059">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24059">

---
## CVE-2023-24058 (2023-01-22T06:15:00)
> Booked Scheduler 2.5.5 allows authenticated users to create and schedule events for any other user via a modified userId value to reservation_save.php. NOTE: 2.5.5 is a version from 2014.
- [Live-Hack-CVE/CVE-2023-24058](https://github.com/Live-Hack-CVE/CVE-2023-24058)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24058">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24058">

---
## CVE-2023-24056 (2023-01-22T04:15:00)
> In pkgconf through 1.9.3, variable duplication can cause unbounded string expansion due to incorrect checks in libpkgconf/tuple.c:pkgconf_tuple_parse. For example, a .pc file containing a few hundred bytes can expand to one billion bytes.
- [Live-Hack-CVE/CVE-2023-24056](https://github.com/Live-Hack-CVE/CVE-2023-24056)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24056">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24056">

---
## CVE-2023-24055 (2023-01-22T04:15:00)
> ** DISPUTED ** KeePass through 2.53 (in a default installation) allows an attacker, who has write access to the XML configuration file, to obtain the cleartext passwords by adding an export trigger. NOTE: the vendor's position is that the password database is not intended to be secure against an attacker who has that level of access to the local PC.
- [Live-Hack-CVE/CVE-2023-24055](https://github.com/Live-Hack-CVE/CVE-2023-24055)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24055">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24055">

---
## CVE-2023-24044 (2023-01-22T03:15:00)
> A Host Header Injection issue on the Login page of Plesk Obsidian through 18.0.49 allows attackers to redirect users to malicious websites via a Host request header.
- [Live-Hack-CVE/CVE-2023-24044](https://github.com/Live-Hack-CVE/CVE-2023-24044)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24044">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24044">

---
## CVE-2023-24042 (2023-01-21T02:15:00)
> A race condition in LightFTP through 2.2 allows an attacker to achieve path traversal via a malformed FTP request. A handler thread can use an overwritten context->FileName.
- [Live-Hack-CVE/CVE-2023-24042](https://github.com/Live-Hack-CVE/CVE-2023-24042)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24042">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24042">

---
## CVE-2023-24040 (2023-01-21T02:15:00)
> ** UNSUPPORTED WHEN ASSIGNED ** dtprintinfo in Common Desktop Environment 1.6 has a bug in the parser of lpstat (an invoked external command) during listing of the names of available printers. This allows low-privileged local users to inject arbitrary printer names via the $HOME/.printers file. This injection allows those users to manipulate the control flow and disclose memory contents on Solaris 10 systems. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.
- [Live-Hack-CVE/CVE-2023-24040](https://github.com/Live-Hack-CVE/CVE-2023-24040)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24040">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24040">

---
## CVE-2023-24039 (2023-01-21T02:15:00)
> ** UNSUPPORTED WHEN ASSIGNED ** A stack-based buffer overflow in ParseColors in libXm in Common Desktop Environment 1.6 can be exploited by local low-privileged users via the dtprintinfo setuid binary to escalate their privileges to root on Solaris 10 systems. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.
- [Live-Hack-CVE/CVE-2023-24039](https://github.com/Live-Hack-CVE/CVE-2023-24039)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24039">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24039">

---
## CVE-2023-24038 (2023-01-21T01:15:00)
> The HTML-StripScripts module through 1.06 for Perl allows _hss_attval_style ReDoS because of catastrophic backtracking for HTML content with certain style attributes.
- [Live-Hack-CVE/CVE-2023-24038](https://github.com/Live-Hack-CVE/CVE-2023-24038)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24038">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24038">

---
## CVE-2023-24028 (2023-01-20T22:15:00)
> In MISP 2.4.167, app/Controller/Component/ACLComponent.php has incorrect access control for the decaying import function.
- [Live-Hack-CVE/CVE-2023-24028](https://github.com/Live-Hack-CVE/CVE-2023-24028)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24028">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24028">

---
## CVE-2023-24027 (2023-01-20T22:15:00)
> In MISP 2.4.167, app/webroot/js/action_table.js allows XSS via a network history name.
- [Live-Hack-CVE/CVE-2023-24027](https://github.com/Live-Hack-CVE/CVE-2023-24027)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24027">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24027">

---
## CVE-2023-24026 (2023-01-20T22:15:00)
> In MISP 2.4.167, app/webroot/js/event-graph.js has an XSS vulnerability via an event-graph preview payload.
- [Live-Hack-CVE/CVE-2023-24026](https://github.com/Live-Hack-CVE/CVE-2023-24026)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24026">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24026">

---
## CVE-2023-24025 (2023-01-20T21:15:00)
> CRYSTALS-DILITHIUM (in Post-Quantum Cryptography Selected Algorithms 2022) in PQClean d03da30 may allow universal forgeries of digital signatures via a template side-channel attack because of intermediate data leakage of one vector.
- [Live-Hack-CVE/CVE-2023-24025](https://github.com/Live-Hack-CVE/CVE-2023-24025)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24025">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24025">

---
## CVE-2023-23749 (2023-01-17T20:15:00)
> The 'LDAP Integration with Active Directory and OpenLDAP - NTLM & Kerberos Login' extension is vulnerable to LDAP Injection since is not properly sanitizing the 'username' POST parameter. An attacker can manipulate this paramter to dump arbitrary contents form the LDAP Database.
- [Live-Hack-CVE/CVE-2023-23749](https://github.com/Live-Hack-CVE/CVE-2023-23749)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23749">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23749">

---
## CVE-2023-23691 (2023-01-20T08:15:00)
> Dell EMC PV ME5, versions ME5.1.0.0.0 and ME5.1.0.1.0, contains a Client-side desync Vulnerability. An unauthenticated attacker could potentially exploit this vulnerability to force a victim's browser to desynchronize its connection with the website, typically leading to XSS and DoS.
- [Live-Hack-CVE/CVE-2023-23691](https://github.com/Live-Hack-CVE/CVE-2023-23691)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23691">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23691">

---
## CVE-2023-23690 (2023-01-19T12:15:00)
> Cloud Mobility for Dell EMC Storage, versions 1.3.0.X and below contains an Improper Check for Certificate Revocation vulnerability. A threat actor does not need any specific privileges to potentially exploit this vulnerability. An attacker could perform a man-in-the-middle attack and eavesdrop on encrypted communications from Cloud Mobility to Cloud Storage devices. Exploitation could lead to the compromise of secret and sensitive information, cloud storage connection downtime, and the integrity of the connection to the Cloud devices.
- [Live-Hack-CVE/CVE-2023-23690](https://github.com/Live-Hack-CVE/CVE-2023-23690)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23690">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23690">

---
## CVE-2023-23607 (2023-01-20T21:15:00)
> erohtar/Dasherr is a dashboard for self-hosted services. In affected versions unrestricted file upload allows any unauthenticated user to execute arbitrary code on the server. The file /www/include/filesave.php allows for any file to uploaded to anywhere. If an attacker uploads a php file they can execute code on the server. This issue has been addressed in version 1.05.00. Users are advised to upgrade. There are no known workarounds for this issue.
- [Live-Hack-CVE/CVE-2023-23607](https://github.com/Live-Hack-CVE/CVE-2023-23607)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23607">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23607">

---
## CVE-2023-23596 (2023-01-20T08:15:00)
> jc21 NGINX Proxy Manager through 2.9.19 allows OS command injection. When creating an access list, the backend builds an htpasswd file with crafted username and/or password input that is concatenated without any validation, and is directly passed to the exec command, potentially allowing an authenticated attacker to execute arbitrary commands on the system. NOTE: this is not part of any NGINX software shipped by F5.
- [Live-Hack-CVE/CVE-2023-23596](https://github.com/Live-Hack-CVE/CVE-2023-23596)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23596">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23596">

---
## CVE-2023-23595 (2023-01-15T07:15:00)
> BlueCat Device Registration Portal 2.2 allows XXE attacks that exfiltrate single-line files. A single-line file might contain credentials, such as "machine example.com login daniel password qwerty" in the documentation example for the .netrc file format. NOTE; 2.x versions are no longer supported. There is no available information about whether any later version is affected.
- [Live-Hack-CVE/CVE-2023-23595](https://github.com/Live-Hack-CVE/CVE-2023-23595)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23595">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23595">

---
## CVE-2023-23590 (2023-01-15T05:15:00)
> Mercedes-Benz XENTRY Retail Data Storage 7.8.1 allows remote attackers to cause a denial of service (device restart) via an unauthenticated API request. The attacker must be on the same network as the device.
- [Live-Hack-CVE/CVE-2023-23590](https://github.com/Live-Hack-CVE/CVE-2023-23590)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23590">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23590">

---
## CVE-2023-23589 (2023-01-14T01:15:00)
> The SafeSocks option in Tor before 0.4.7.13 has a logic error in which the unsafe SOCKS4 protocol can be used but not the safe SOCKS4a protocol, aka TROVE-2022-002.
- [Live-Hack-CVE/CVE-2023-23589](https://github.com/Live-Hack-CVE/CVE-2023-23589)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23589">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23589">

---
## CVE-2023-23559 (2023-01-13T01:15:00)
> In rndis_query_oid in drivers/net/wireless/rndis_wlan.c in the Linux kernel through 6.1.5, there is an integer overflow in an addition.
- [Live-Hack-CVE/CVE-2023-23559](https://github.com/Live-Hack-CVE/CVE-2023-23559)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23559">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23559">

---
## CVE-2023-23489 (2023-01-20T18:15:00)
> The Easy Digital Downloads WordPress Plugin, version < 3.1.0.4, is affected by an unauthenticated SQL injection vulnerability in the 's' parameter of its 'edd_download_search' action.
- [Live-Hack-CVE/CVE-2023-23489](https://github.com/Live-Hack-CVE/CVE-2023-23489)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23489">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23489">

---
## CVE-2023-23488 (2023-01-20T18:15:00)
> The Paid Memberships Pro WordPress Plugin, version < 2.9.8, is affected by an unauthenticated SQL injection vulnerability in the 'code' parameter of the '/pmpro/v1/order' REST route.
- [Live-Hack-CVE/CVE-2023-23488](https://github.com/Live-Hack-CVE/CVE-2023-23488)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23488">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23488">

---
## CVE-2023-23457 (2023-01-12T19:15:00)
> A Segmentation fault was found in UPX in PackLinuxElf64::invert_pt_dynamic() in p_lx_elf.cpp. An attacker with a crafted input file allows invalid memory address access that could lead to a denial of service.
- [Live-Hack-CVE/CVE-2023-23457](https://github.com/Live-Hack-CVE/CVE-2023-23457)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23457">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23457">

---
## CVE-2023-23456 (2023-01-12T19:15:00)
> A heap-based buffer overflow issue was discovered in UPX in PackTmt::pack() in p_tmt.cpp file. The flow allows an attacker to cause a denial of service (abort) via a crafted file.
- [Live-Hack-CVE/CVE-2023-23456](https://github.com/Live-Hack-CVE/CVE-2023-23456)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23456">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23456">

---
## CVE-2023-23455 (2023-01-12T07:15:00)
> atm_tc_enqueue in net/sched/sch_atm.c in the Linux kernel through 6.1.4 allows attackers to cause a denial of service because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition rather than valid classification results).
- [Live-Hack-CVE/CVE-2023-23455](https://github.com/Live-Hack-CVE/CVE-2023-23455)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23455">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23455">

---
## CVE-2023-23454 (2023-01-12T07:15:00)
> cbq_classify in net/sched/sch_cbq.c in the Linux kernel through 6.1.4 allows attackers to cause a denial of service (slab-out-of-bounds read) because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition rather than valid classification results).
- [Live-Hack-CVE/CVE-2023-23454](https://github.com/Live-Hack-CVE/CVE-2023-23454)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23454">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23454">

---
## CVE-2023-23314 (2023-01-23T05:15:00)
> An arbitrary file upload vulnerability in the /api/upload component of zdir v3.2.0 allows attackers to execute arbitrary code via a crafted .ssh file.
- [Live-Hack-CVE/CVE-2023-23314](https://github.com/Live-Hack-CVE/CVE-2023-23314)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23314">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23314">

---
## CVE-2023-23163 ()
> 
- [rahulpatwari/CVE-2023-23163](https://github.com/rahulpatwari/CVE-2023-23163)	<img alt="forks" src="https://img.shields.io/github/forks/rahulpatwari/CVE-2023-23163">	<img alt="stars" src="https://img.shields.io/github/stars/rahulpatwari/CVE-2023-23163">

---
## CVE-2023-23162 ()
> 
- [rahulpatwari/CVE-2023-23162](https://github.com/rahulpatwari/CVE-2023-23162)	<img alt="forks" src="https://img.shields.io/github/forks/rahulpatwari/CVE-2023-23162">	<img alt="stars" src="https://img.shields.io/github/stars/rahulpatwari/CVE-2023-23162">

---
## CVE-2023-23161 ()
> 
- [rahulpatwari/CVE-2023-23161](https://github.com/rahulpatwari/CVE-2023-23161)	<img alt="forks" src="https://img.shields.io/github/forks/rahulpatwari/CVE-2023-23161">	<img alt="stars" src="https://img.shields.io/github/stars/rahulpatwari/CVE-2023-23161">

---
## CVE-2023-22963 (2023-01-11T06:15:00)
> The personnummer implementation before 3.0.3 for Dart mishandles numbers in which the last four digits match the ^000[0-9]$ regular expression.
- [Live-Hack-CVE/CVE-2023-22963](https://github.com/Live-Hack-CVE/CVE-2023-22963)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22963">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22963">

---
## CVE-2023-22959 (2023-01-11T04:15:00)
> WebChess through 0.9.0 and 1.0.0.rc2 allows SQL injection: mainmenu.php, chess.php, and opponentspassword.php (txtFirstName, txtLastName).
- [Live-Hack-CVE/CVE-2023-22959](https://github.com/Live-Hack-CVE/CVE-2023-22959)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22959">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22959">

---
## CVE-2023-22958 (2023-01-11T03:15:00)
> The Syracom Secure Login plugin before 3.1.1.0 for Jira may allow spoofing of 2FA PIN validation via the plugins/servlet/twofactor/public/pinvalidation target parameter.
- [Live-Hack-CVE/CVE-2023-22958](https://github.com/Live-Hack-CVE/CVE-2023-22958)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22958">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22958">

---
## CVE-2023-22952 (2023-01-11T09:15:00)
> In SugarCRM before 12.0. Hotfix 91155, a crafted request can inject custom PHP code through the EmailTemplates because of missing input validation.
- [Live-Hack-CVE/CVE-2023-22952](https://github.com/Live-Hack-CVE/CVE-2023-22952)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22952">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22952">

---
## CVE-2023-22945 (2023-01-11T01:15:00)
> In the GrowthExperiments extension for MediaWiki through 1.39, the growthmanagementorlist API allows blocked users (blocked in ApiManageMentorList) to enroll as mentors or edit any of their mentorship-related properties.
- [Live-Hack-CVE/CVE-2023-22945](https://github.com/Live-Hack-CVE/CVE-2023-22945)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22945">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22945">

---
## CVE-2023-22912 (2023-01-20T18:15:00)
> An issue was discovered in MediaWiki before 1.35.9, 1.36.x through 1.38.x before 1.38.5, and 1.39.x before 1.39.1. CheckUser TokenManager insecurely uses AES-CTR encryption with a repeated (aka re-used) nonce, allowing an adversary to decrypt.
- [Live-Hack-CVE/CVE-2023-22912](https://github.com/Live-Hack-CVE/CVE-2023-22912)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22912">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22912">

---
## CVE-2023-22911 (2023-01-10T08:15:00)
> An issue was discovered in MediaWiki before 1.35.9, 1.36.x through 1.38.x before 1.38.5, and 1.39.x before 1.39.1. E-Widgets does widget replacement in HTML attributes, which can lead to XSS, because widget authors often do not expect that their widget is executed in an HTML attribute context.
- [Live-Hack-CVE/CVE-2023-22911](https://github.com/Live-Hack-CVE/CVE-2023-22911)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22911">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22911">

---
## CVE-2023-22910 (2023-01-20T18:15:00)
> An issue was discovered in MediaWiki before 1.35.9, 1.36.x through 1.38.x before 1.38.5, and 1.39.x before 1.39.1. There is XSS in Wikibase date formatting via wikibase-time-precision-* fields. This allows JavaScript execution by staff/admin users who do not intentionally have the editsitejs capability.
- [Live-Hack-CVE/CVE-2023-22910](https://github.com/Live-Hack-CVE/CVE-2023-22910)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22910">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22910">

---
## CVE-2023-22909 (2023-01-10T08:15:00)
> An issue was discovered in MediaWiki before 1.35.9, 1.36.x through 1.38.x before 1.38.5, and 1.39.x before 1.39.1. SpecialMobileHistory allows remote attackers to cause a denial of service because database queries are slow.
- [Live-Hack-CVE/CVE-2023-22909](https://github.com/Live-Hack-CVE/CVE-2023-22909)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22909">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22909">

---
## CVE-2023-22903 (2023-01-10T06:15:00)
> api/views/user.py in LibrePhotos before e19e539 has incorrect access control.
- [Live-Hack-CVE/CVE-2023-22903](https://github.com/Live-Hack-CVE/CVE-2023-22903)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22903">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22903">

---
## CVE-2023-22885 (2023-01-11T08:15:00)
> ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.
- [Live-Hack-CVE/CVE-2023-22885](https://github.com/Live-Hack-CVE/CVE-2023-22885)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22885">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22885">

---
## CVE-2023-22884 (2023-01-21T14:15:00)
> Improper Neutralization of Special Elements used in a Command ('Command Injection') vulnerability in Apache Software Foundation Apache Airflow, Apache Software Foundation Apache Airflow MySQL Provider.This issue affects Apache Airflow: before 2.5.1; Apache Airflow MySQL Provider: before 4.0.0.
- [Live-Hack-CVE/CVE-2023-22884](https://github.com/Live-Hack-CVE/CVE-2023-22884)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22884">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22884">

---
## CVE-2023-22855 ()
> 
- [patrickhener/CVE-2023-22855](https://github.com/patrickhener/CVE-2023-22855)	<img alt="forks" src="https://img.shields.io/github/forks/patrickhener/CVE-2023-22855">	<img alt="stars" src="https://img.shields.io/github/stars/patrickhener/CVE-2023-22855">

---
## CVE-2023-22809 (2023-01-18T17:15:00)
> In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a "--" argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.
- [Live-Hack-CVE/CVE-2023-22809](https://github.com/Live-Hack-CVE/CVE-2023-22809)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22809">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22809">
- [n3m1dotsys/CVE-2023-22809-sudoedit-privesc](https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc)	<img alt="forks" src="https://img.shields.io/github/forks/n3m1dotsys/CVE-2023-22809-sudoedit-privesc">	<img alt="stars" src="https://img.shields.io/github/stars/n3m1dotsys/CVE-2023-22809-sudoedit-privesc">

---
## CVE-2023-22745 (2023-01-19T23:15:00)
> tpm2-tss is an open source software implementation of the Trusted Computing Group (TCG) Trusted Platform Module (TPM) 2 Software Stack (TSS2). In affected versions `Tss2_RC_SetHandler` and `Tss2_RC_Decode` both index into `layer_handler` with an 8 bit layer number, but the array only has `TPM2_ERROR_TSS2_RC_LAYER_COUNT` entries, so trying to add a handler for higher-numbered layers or decode a response code with such a layer number reads/writes past the end of the buffer. This Buffer overrun, could result in arbitrary code execution. An example attack would be a MiTM bus attack that returns 0xFFFFFFFF for the RC. Given the common use case of TPM modules an attacker must have local access to the target machine with local system privileges which allows access to the TPM system. Usually TPM access requires administrative privilege.
- [Live-Hack-CVE/CVE-2023-22745](https://github.com/Live-Hack-CVE/CVE-2023-22745)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22745">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22745">

---
## CVE-2023-22742 (2023-01-20T23:15:00)
> libgit2 is a cross-platform, linkable library implementation of Git. When using an SSH remote with the optional libssh2 backend, libgit2 does not perform certificate checking by default. Prior versions of libgit2 require the caller to set the `certificate_check` field of libgit2's `git_remote_callbacks` structure - if a certificate check callback is not set, libgit2 does not perform any certificate checking. This means that by default - without configuring a certificate check callback, clients will not perform validation on the server SSH keys and may be subject to a man-in-the-middle attack. Users are encouraged to upgrade to v1.4.5 or v1.5.1. Users unable to upgrade should ensure that all relevant certificates are manually checked.
- [Live-Hack-CVE/CVE-2023-22742](https://github.com/Live-Hack-CVE/CVE-2023-22742)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22742">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22742">

---
## CVE-2023-22741 (2023-01-19T22:15:00)
> Sofia-SIP is an open-source SIP User-Agent library, compliant with the IETF RFC3261 specification. In affected versions Sofia-SIP **lacks both message length and attributes length checks** when it handles STUN packets, leading to controllable heap-over-flow. For example, in stun_parse_attribute(), after we get the attribute's type and length value, the length will be used directly to copy from the heap, regardless of the message's left size. Since network users control the overflowed length, and the data is written to heap chunks later, attackers may achieve remote code execution by heap grooming or other exploitation methods. The bug was introduced 16 years ago in sofia-sip 1.12.4 (plus some patches through 12/21/2006) to in tree libs with git-svn-id: http://svn.freeswitch.org/svn/freeswitch/trunk@3774 d0543943-73ff-0310-b7d9-9358b9ac24b2. Users are advised to upgrade. There are no known workarounds for this vulnerability.
- [Live-Hack-CVE/CVE-2023-22741](https://github.com/Live-Hack-CVE/CVE-2023-22741)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22741">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22741">

---
## CVE-2023-22734 (2023-01-17T22:15:00)
> Shopware is an open source commerce platform based on Symfony Framework and Vue js. The newsletter double opt-in validation was not checked properly, and it was possible to skip the complete double opt in process. As a result operators may have inconsistencies in their newsletter systems. This problem has been fixed with version 6.4.18.1. Users are advised to upgrade. Users unable to upgrade may find security measures are available via a plugin for major versions 6.1, 6.2, and 6.3. Users may also disable newsletter registration completely.
- [Live-Hack-CVE/CVE-2023-22734](https://github.com/Live-Hack-CVE/CVE-2023-22734)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22734">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22734">

---
## CVE-2023-22733 (2023-01-17T22:15:00)
> Shopware is an open source commerce platform based on Symfony Framework and Vue js. In affected versions the log module would write out all kind of sent mails. An attacker with access to either the local system logs or a centralized logging store may have access to other users accounts. This issue has been addressed in version 6.4.18.1. For older versions of 6.1, 6.2, and 6.3, corresponding security measures are also available via a plugin. For the full range of functions, we recommend updating to the latest Shopware version. Users unable to upgrade may remove from all users the log module ACL rights or disable logging.
- [Live-Hack-CVE/CVE-2023-22733](https://github.com/Live-Hack-CVE/CVE-2023-22733)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22733">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22733">

---
## CVE-2023-22732 (2023-01-17T22:15:00)
> Shopware is an open source commerce platform based on Symfony Framework and Vue js. The Administration session expiration was set to one week, when an attacker has stolen the session cookie they could use it for a long period of time. In version 6.4.18.1 an automatic logout into the Administration session has been added. As a result the user will be logged out when they are inactive. Users are advised to upgrade. There are no known workarounds for this issue.
- [Live-Hack-CVE/CVE-2023-22732](https://github.com/Live-Hack-CVE/CVE-2023-22732)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22732">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22732">

---
## CVE-2023-22731 (2023-01-17T22:15:00)
> Shopware is an open source commerce platform based on Symfony Framework and Vue js. In a Twig environment **without the Sandbox extension**, it is possible to refer to PHP functions in twig filters like `map`, `filter`, `sort`. This allows a template to call any global PHP function and thus execute arbitrary code. The attacker must have access to a Twig environment in order to exploit this vulnerability. This problem has been fixed with 6.4.18.1 with an override of the specified filters until the integration of the Sandbox extension has been finished. Users are advised to upgrade. Users of major versions 6.1, 6.2, and 6.3 may also receive this fix via a plugin.
- [Live-Hack-CVE/CVE-2023-22731](https://github.com/Live-Hack-CVE/CVE-2023-22731)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22731">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22731">

---
## CVE-2023-22730 (2023-01-17T22:15:00)
> Shopware is an open source commerce platform based on Symfony Framework and Vue js. In affected versions It was possible to put the same line item multiple times in the cart using the AP. The Cart Validators checked the line item's individuality and the user was able to bypass quantity limits in sales. This problem has been fixed with version 6.4.18.1. Users on major versions 6.1, 6.2, and 6.3 may also obtain this fix via a plugin.
- [Live-Hack-CVE/CVE-2023-22730](https://github.com/Live-Hack-CVE/CVE-2023-22730)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22730">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22730">

---
## CVE-2023-22726 (2023-01-20T22:15:00)
> act is a project which allows for local running of github actions. The artifact server that stores artifacts from Github Action runs does not sanitize path inputs. This allows an attacker to download and overwrite arbitrary files on the host from a Github Action. This issue may lead to privilege escalation. The /upload endpoint is vulnerable to path traversal as filepath is user controlled, and ultimately flows into os.Mkdir and os.Open. The /artifact endpoint is vulnerable to path traversal as the path is variable is user controlled, and the specified file is ultimately returned by the server. This has been addressed in version 0.2.40. Users are advised to upgrade. Users unable to upgrade may, during implementation of Open and OpenAtEnd for FS, ensure to use ValidPath() to check against path traversal or clean the user-provided paths manually.
- [Live-Hack-CVE/CVE-2023-22726](https://github.com/Live-Hack-CVE/CVE-2023-22726)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22726">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22726">

---
## CVE-2023-22671 (2023-01-06T07:15:00)
> Ghidra/RuntimeScripts/Linux/support/launch.sh in NSA Ghidra through 10.2.2 passes user-provided input into eval, leading to command injection when calling analyzeHeadless with untrusted input.
- [Live-Hack-CVE/CVE-2023-22671](https://github.com/Live-Hack-CVE/CVE-2023-22671)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22671">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22671">

---
## CVE-2023-22626 (2023-01-05T08:15:00)
> PgHero before 3.1.0 allows Information Disclosure via EXPLAIN because query results may be present in an error message. (Depending on database user privileges, this may only be information from the database, or may be information from file contents on the database server.)
- [Live-Hack-CVE/CVE-2023-22626](https://github.com/Live-Hack-CVE/CVE-2023-22626)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22626">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22626">

---
## CVE-2023-22624 (2023-01-17T20:15:00)
> Zoho ManageEngine Exchange Reporter Plus before 5708 allows attackers to conduct XXE attacks.
- [Live-Hack-CVE/CVE-2023-22624](https://github.com/Live-Hack-CVE/CVE-2023-22624)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22624">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22624">

---
## CVE-2023-22622 (2023-01-05T02:15:00)
> WordPress through 6.1.1 depends on unpredictable client visits to cause wp-cron.php execution and the resulting security updates, and the source code describes "the scenario where a site may not receive enough visits to execute scheduled tasks in a timely manner," but neither the installation guide nor the security guide mentions this default behavior, or alerts the user about security risks on installations with very few visits.
- [Live-Hack-CVE/CVE-2023-22622](https://github.com/Live-Hack-CVE/CVE-2023-22622)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22622">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22622">

---
## CVE-2023-22617 (2023-01-21T19:15:00)
> A remote attacker might be able to cause infinite recursion in PowerDNS Recursor 4.8.0 via a DNS query that retrieves DS records for a misconfigured domain, because QName minimization is used in QM fallback mode. This is fixed in 4.8.1.
- [Live-Hack-CVE/CVE-2023-22617](https://github.com/Live-Hack-CVE/CVE-2023-22617)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22617">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22617">

---
## CVE-2023-22602 (2023-01-14T10:15:00)
> When using Apache Shiro before 1.11.0 together with Spring Boot 2.6+, a specially crafted HTTP request may cause an authentication bypass. The authentication bypass occurs when Shiro and Spring Boot are using different pattern-matching techniques. Both Shiro and Spring Boot < 2.6 default to Ant style pattern matching. Mitigation: Update to Apache Shiro 1.11.0, or set the following Spring Boot configuration value: `spring.mvc.pathmatch.matching-strategy = ant_path_matcher`
- [Live-Hack-CVE/CVE-2023-22602](https://github.com/Live-Hack-CVE/CVE-2023-22602)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22602">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22602">

---
## CVE-2023-22551 (2023-01-01T18:15:00)
> The FTP (aka "Implementation of a simple FTP client and server") project through 96c1a35 allows remote attackers to cause a denial of service (memory consumption) by engaging in client activity, such as establishing and then terminating a connection. This occurs because malloc is used but free is not.
- [Live-Hack-CVE/CVE-2023-22551](https://github.com/Live-Hack-CVE/CVE-2023-22551)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22551">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22551">

---
## CVE-2023-22494 (2023-01-13T16:15:00)
> a12nserver is an open source lightweight OAuth2 server. Users of a12nserver that use MySQL might be vulnerable to SQL injection bugs. If you use a12nserver and MySQL, update as soon as possible. This SQL injection bug might let an attacker obtain OAuth2 Access Tokens for users unrelated to those that permitted OAuth2 clients. The knex dependency has been updated to 2.4.0 in a12nserver 0.23.0. There are no known workarounds.
- [Live-Hack-CVE/CVE-2023-22494](https://github.com/Live-Hack-CVE/CVE-2023-22494)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22494">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22494">

---
## CVE-2023-22492 (2023-01-11T20:15:00)
> ZITADEL is a combination of Auth0 and Keycloak. RefreshTokens is an OAuth 2.0 feature that allows applications to retrieve new access tokens and refresh the user's session without the need for interacting with a UI. RefreshTokens were not invalidated when a user was locked or deactivated. The deactivated or locked user was able to obtain a valid access token only through a refresh token grant. When the locked or deactivated user’s session was already terminated (“logged out”) then it was not possible to create a new session. Renewal of access token through a refresh token grant is limited to the configured amount of time (RefreshTokenExpiration). As a workaround, ensure the RefreshTokenExpiration in the OIDC settings of your instance is set according to your security requirements. This issue has been patched in versions 2.17.3 and 2.16.4.
- [Live-Hack-CVE/CVE-2023-22492](https://github.com/Live-Hack-CVE/CVE-2023-22492)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22492">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22492">

---
## CVE-2023-22491 (2023-01-13T19:15:00)
> Gatsby is a free and open source framework based on React that helps developers build websites and apps. The gatsby-transformer-remark plugin prior to versions 5.25.1 and 6.3.2 passes input through to the `gray-matter` npm package, which is vulnerable to JavaScript injection in its default configuration, unless input is sanitized. The vulnerability is present in gatsby-transformer-remark when passing input in data mode (querying MarkdownRemark nodes via GraphQL). Injected JavaScript executes in the context of the build server. To exploit this vulnerability untrusted/unsanitized input would need to be sourced by or added into a file processed by gatsby-transformer-remark. A patch has been introduced in `gatsby-transformer-remark@5.25.1` and `gatsby-transformer-remark@6.3.2` which mitigates the issue by disabling the `gray-matter` JavaScript Frontmatter engine. As a workaround, if an older version of `gatsby-transformer-remark` must be used, input passed into the plugin should be sanitized ahead of processing. It is encouraged for projects to upgrade to the latest major release branch for all Gatsby plugins to ensure the latest security updates and bug fixes are received in a timely manner.
- [Live-Hack-CVE/CVE-2023-22491](https://github.com/Live-Hack-CVE/CVE-2023-22491)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22491">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22491">

---
## CVE-2023-22489 (2023-01-13T19:15:00)
> Flarum is a discussion platform for websites. If the first post of a discussion is permanently deleted but the discussion stays visible, any actor who can view the discussion is able to create a new reply via the REST API, no matter the reply permission or lock status. This includes users that don't have a validated email. Guests cannot successfully create a reply because the API will fail with a 500 error when the user ID 0 is inserted into the database. This happens because when the first post of a discussion is permanently deleted, the `first_post_id` attribute of the discussion becomes `null` which causes access control to be skipped for all new replies. Flarum automatically makes discussions with zero comments invisible so an additional condition for this vulnerability is that the discussion must have at least one approved reply so that `discussions.comment_count` is still above zero after the post deletion. This can open the discussion to uncontrolled spam or just unintentional replies if users still had their tab open before the vulnerable discussion was locked and then post a reply when they shouldn't be able to. In combination with the email notification settings, this could also be used as a way to send unsolicited emails. Versions between `v1.3.0` and `v1.6.3` are impacted. The vulnerability has been fixed and published as flarum/core v1.6.3. All communities running Flarum should upgrade as soon as possible. There are no known workarounds.
- [Live-Hack-CVE/CVE-2023-22489](https://github.com/Live-Hack-CVE/CVE-2023-22489)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22489">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22489">

---
## CVE-2023-22488 (2023-01-12T20:15:00)
> Flarum is a forum software for building communities. Using the notifications feature, one can read restricted/private content and bypass access checks that would be in place for such content. The notification-sending component does not check that the subject of the notification can be seen by the receiver, and proceeds to send notifications through their different channels. The alerts do not leak data despite this as they are listed based on a visibility check, however, emails are still sent out. This means that, for extensions which restrict access to posts, any actor can bypass the restriction by subscribing to the discussion if the Subscriptions extension is enabled. The attack allows the leaking of some posts in the forum database, including posts awaiting approval, posts in tags the user has no access to if they could subscribe to a discussion before it becomes private, and posts restricted by third-party extensions. All Flarum versions prior to v1.6.3 are affected. The vulnerability has been fixed and published as flarum/core v1.6.3. All communities running Flarum should upgrade as soon as possible to v1.6.3. As a workaround, disable the Flarum Subscriptions extension or disable email notifications altogether. There are no other supported workarounds for this issue for Flarum versions below 1.6.3.
- [Live-Hack-CVE/CVE-2023-22488](https://github.com/Live-Hack-CVE/CVE-2023-22488)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22488">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22488">

---
## CVE-2023-22487 (2023-01-11T20:15:00)
> Flarum is a forum software for building communities. Using the mentions feature provided by the flarum/mentions extension, users can mention any post ID on the forum with the special `@"<username>"#p<id>` syntax. The following behavior never changes no matter if the actor should be able to read the mentioned post or not: A URL to the mentioned post is inserted into the actor post HTML, leaking its discussion ID and post number. The `mentionsPosts` relationship included in the `POST /api/posts` and `PATCH /api/posts/<id>` JSON responses leaks the full JSON:API payload of all mentioned posts without any access control. This includes the content, date, number and attributes added by other extensions. An attacker only needs the ability to create new posts on the forum to exploit the vulnerability. This works even if new posts require approval. If they have the ability to edit posts, the attack can be performed even more discreetly by using a single post to scan any size of database and hiding the attack post content afterward. The attack allows the leaking of all posts in the forum database, including posts awaiting approval, posts in tags the user has no access to, and private discussions created by other extensions like FriendsOfFlarum Byobu. This also includes non-comment posts like tag changes or renaming events. The discussion payload is not leaked but using the mention HTML payload it's possible to extract the discussion ID of all posts and combine all posts back together into their original discussions even if the discussion title remains unknown. All Flarum versions prior to 1.6.3 are affected. The vulnerability has been fixed and published as flarum/core v1.6.3. As a workaround, user can disable the mentions extension.
- [Live-Hack-CVE/CVE-2023-22487](https://github.com/Live-Hack-CVE/CVE-2023-22487)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22487">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22487">

---
## CVE-2023-22479 (2023-01-10T21:15:00)
> KubePi is a modern Kubernetes panel. A session fixation attack allows an attacker to hijack a legitimate user session, versions 1.6.3 and below are susceptible. A patch will be released in version 1.6.4.
- [Live-Hack-CVE/CVE-2023-22479](https://github.com/Live-Hack-CVE/CVE-2023-22479)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22479">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22479">

---
## CVE-2023-22477 (2023-01-09T15:15:00)
> Mercurius is a GraphQL adapter for Fastify. Any users of Mercurius until version 10.5.0 are subjected to a denial of service attack by sending a malformed packet over WebSocket to `/graphql`. This issue was patched in #940. As a workaround, users can disable subscriptions.
- [Live-Hack-CVE/CVE-2023-22477](https://github.com/Live-Hack-CVE/CVE-2023-22477)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22477">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22477">

---
## CVE-2023-22475 (2023-01-06T15:15:00)
> Canarytokens is an open source tool which helps track activity and actions on your network. A Cross-Site Scripting vulnerability was identified in the history page of triggered Canarytokens prior to sha-fb61290. An attacker who discovers an HTTP-based Canarytoken (a URL) can use this to execute Javascript in the Canarytoken's trigger history page (domain: canarytokens.org) when the history page is later visited by the Canarytoken's creator. This vulnerability could be used to disable or delete the affected Canarytoken, or view its activation history. It might also be used as a stepping stone towards revealing more information about the Canarytoken's creator to the attacker. For example, an attacker could recover the email address tied to the Canarytoken, or place Javascript on the history page that redirect the creator towards an attacker-controlled Canarytoken to show the creator's network location. This vulnerability is similar to CVE-2022-31113, but affected parameters reported differently from the Canarytoken trigger request. An attacker could only act on the discovered Canarytoken. This issue did not expose other Canarytokens or other Canarytoken creators. Canarytokens Docker images sha-fb61290 and later contain a patch for this issue.
- [Live-Hack-CVE/CVE-2023-22475](https://github.com/Live-Hack-CVE/CVE-2023-22475)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22475">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22475">

---
## CVE-2023-22472 (2023-01-09T14:15:00)
> Deck is a kanban style organization tool aimed at personal planning and project organization for teams integrated with Nextcloud. It is possible to make a user send any POST request with an arbitrary body given they click on a malicious deep link on a Windows computer. (e.g. in an email, chat link, etc). There are currently no known workarounds. It is recommended that the Nextcloud Desktop client is upgraded to 3.6.2.
- [Live-Hack-CVE/CVE-2023-22472](https://github.com/Live-Hack-CVE/CVE-2023-22472)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22472">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22472">

---
## CVE-2023-22469 (2023-01-10T21:15:00)
> Deck is a kanban style organization tool aimed at personal planning and project organization for teams integrated with Nextcloud. When getting the reference preview for Deck cards the user has no access to, unauthorized user could eventually get the cached data of a user that has access. There are currently no known workarounds. It is recommended that the Nextcloud app Deck is upgraded to 1.8.2.
- [Live-Hack-CVE/CVE-2023-22469](https://github.com/Live-Hack-CVE/CVE-2023-22469)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22469">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22469">

---
## CVE-2023-22467 (2023-01-04T22:15:00)
> Luxon is a library for working with dates and times in JavaScript. On the 1.x branch prior to 1.38.1, the 2.x branch prior to 2.5.2, and the 3.x branch on 3.2.1, Luxon's `DateTime.fromRFC2822() has quadratic (N^2) complexity on some specific inputs. This causes a noticeable slowdown for inputs with lengths above 10k characters. Users providing untrusted data to this method are therefore vulnerable to (Re)DoS attacks. This issue also appears in Moment as CVE-2022-31129. Versions 1.38.1, 2.5.2, and 3.2.1 contain patches for this issue. As a workaround, limit the length of the input.
- [Live-Hack-CVE/CVE-2023-22467](https://github.com/Live-Hack-CVE/CVE-2023-22467)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22467">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22467">

---
## CVE-2023-22466 (2023-01-04T22:15:00)
> Tokio is a runtime for writing applications with Rust. Starting with version 1.7.0 and prior to versions 1.18.4, 1.20.3, and 1.23.1, when configuring a Windows named pipe server, setting `pipe_mode` will reset `reject_remote_clients` to `false`. If the application has previously configured `reject_remote_clients` to `true`, this effectively undoes the configuration. Remote clients may only access the named pipe if the named pipe's associated path is accessible via a publicly shared folder (SMB). Versions 1.23.1, 1.20.3, and 1.18.4 have been patched. The fix will also be present in all releases starting from version 1.24.0. Named pipes were introduced to Tokio in version 1.7.0, so releases older than 1.7.0 are not affected. As a workaround, ensure that `pipe_mode` is set first after initializing a `ServerOptions`.
- [Live-Hack-CVE/CVE-2023-22466](https://github.com/Live-Hack-CVE/CVE-2023-22466)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22466">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22466">

---
## CVE-2023-22464 (2023-01-04T16:15:00)
> ViewVC is a browser interface for CVS and Subversion version control repositories. Versions prior to 1.2.3 and 1.1.30 are vulnerable to cross-site scripting. The impact of this vulnerability is mitigated by the need for an attacker to have commit privileges to a Subversion repository exposed by an otherwise trusted ViewVC instance. The attack vector involves files with unsafe names (names that, when embedded into an HTML stream, would cause the browser to run unwanted code), which themselves can be challenging to create. Users should update to at least version 1.2.3 (if they are using a 1.2.x version of ViewVC) or 1.1.30 (if they are using a 1.1.x version). ViewVC 1.0.x is no longer supported, so users of that release lineage should implement one of the following workarounds. Users can edit their ViewVC EZT view templates to manually HTML-escape changed path "copyfrom paths" during rendering. Locate in your template set's `revision.ezt` file references to those changed paths, and wrap them with `[format "html"]` and `[end]`. For most users, that means that references to `[changes.copy_path]` will become `[format "html"][changes.copy_path][end]`. (This workaround should be reverted after upgrading to a patched version of ViewVC, else "copyfrom path" names will be doubly escaped.)
- [Live-Hack-CVE/CVE-2023-22464](https://github.com/Live-Hack-CVE/CVE-2023-22464)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22464">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22464">

---
## CVE-2023-22463 (2023-01-04T16:15:00)
> KubePi is a k8s panel. The jwt authentication function of KubePi through version 1.6.2 uses hard-coded Jwtsigkeys, resulting in the same Jwtsigkeys for all online projects. This means that an attacker can forge any jwt token to take over the administrator account of any online project. Furthermore, they may use the administrator to take over the k8s cluster of the target enterprise. `session.go`, the use of hard-coded JwtSigKey, allows an attacker to use this value to forge jwt tokens arbitrarily. The JwtSigKey is confidential and should not be hard-coded in the code. The vulnerability has been fixed in 1.6.3. In the patch, JWT key is specified in app.yml. If the user leaves it blank, a random key will be used. There are no workarounds aside from upgrading.
- [Live-Hack-CVE/CVE-2023-22463](https://github.com/Live-Hack-CVE/CVE-2023-22463)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22463">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22463">

---
## CVE-2023-22456 (2023-01-03T19:15:00)
> ViewVC, a browser interface for CVS and Subversion version control repositories, as a cross-site scripting vulnerability that affects versions prior to 1.2.2 and 1.1.29. The impact of this vulnerability is mitigated by the need for an attacker to have commit privileges to a Subversion repository exposed by an otherwise trusted ViewVC instance. The attack vector involves files with unsafe names (names that, when embedded into an HTML stream, would cause the browser to run unwanted code), which themselves can be challenging to create. Users should update to at least version 1.2.2 (if they are using a 1.2.x version of ViewVC) or 1.1.29 (if they are using a 1.1.x version). ViewVC 1.0.x is no longer supported, so users of that release lineage should implement a workaround. Users can edit their ViewVC EZT view templates to manually HTML-escape changed paths during rendering. Locate in your template set's `revision.ezt` file references to those changed paths, and wrap them with `[format "html"]` and `[end]`. For most users, that means that references to `[changes.path]` will become `[format "html"][changes.path][end]`. (This workaround should be reverted after upgrading to a patched version of ViewVC, else changed path names will be doubly escaped.)
- [Live-Hack-CVE/CVE-2023-22456](https://github.com/Live-Hack-CVE/CVE-2023-22456)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22456">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22456">

---
## CVE-2023-22454 (2023-01-05T20:15:00)
> Discourse is an option source discussion platform. Prior to version 2.8.14 on the `stable` branch and version 3.0.0.beta16 on the `beta` and `tests-passed` branches, pending post titles can be used for cross-site scripting attacks. Pending posts can be created by unprivileged users when a category has the "require moderator approval of all new topics" setting set. This vulnerability can lead to a full XSS on sites which have modified or disabled Discourse’s default Content Security Policy. A patch is available in versions 2.8.14 and 3.0.0.beta16.
- [Live-Hack-CVE/CVE-2023-22454](https://github.com/Live-Hack-CVE/CVE-2023-22454)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22454">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22454">

---
## CVE-2023-22453 (2023-01-05T20:15:00)
> Discourse is an option source discussion platform. Prior to version 2.8.14 on the `stable` branch and version 3.0.0.beta16 on the `beta` and `tests-passed` branches, the number of times a user posted in an arbitrary topic is exposed to unauthorized users through the `/u/username.json` endpoint. The issue is patched in version 2.8.14 and 3.0.0.beta16. There is no known workaround.
- [Live-Hack-CVE/CVE-2023-22453](https://github.com/Live-Hack-CVE/CVE-2023-22453)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22453">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22453">

---
## CVE-2023-22452 (2023-01-02T20:15:00)
> kenny2automate is a Discord bot. In the web interface for server settings, form elements were generated with Discord channel IDs as part of input names. Prior to commit a947d7c, no validation was performed to ensure that the channel IDs submitted actually belonged to the server being configured. Thus anyone who has access to the channel ID they wish to change settings for and the server settings panel for any server could change settings for the requested channel no matter which server it belonged to. Commit a947d7c resolves the issue and has been deployed to the official instance of the bot. The only workaround that exists is to disable the web config entirely by changing it to run on localhost. Note that a workaround is only necessary for those who run their own instance of the bot.
- [Live-Hack-CVE/CVE-2023-22452](https://github.com/Live-Hack-CVE/CVE-2023-22452)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22452">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22452">

---
## CVE-2023-22451 (2023-01-02T16:15:00)
> Kiwi TCMS is an open source test management system. In version 11.6 and prior, when users register new accounts and/or change passwords, there is no validation in place which would prevent them from picking an easy to guess password. This issue is resolved by providing defaults for the `AUTH_PASSWORD_VALIDATORS` configuration setting. As of version 11.7, the password can’t be too similar to other personal information, must contain at least 10 characters, can’t be a commonly used password, and can’t be entirely numeric. As a workaround, an administrator may reset all passwords in Kiwi TCMS if they think a weak password may have been chosen.
- [Live-Hack-CVE/CVE-2023-22451](https://github.com/Live-Hack-CVE/CVE-2023-22451)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22451">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22451">

---
## CVE-2023-22417 (2023-01-13T00:15:00)
> A Missing Release of Memory after Effective Lifetime vulnerability in the Flow Processing Daemon (flowd) of Juniper Networks Junos OS allows a network-based, unauthenticated attacker to cause a Denial of Service (DoS). In an IPsec VPN environment, a memory leak will be seen if a DH or ECDH group is configured. Eventually the flowd process will crash and restart. This issue affects Juniper Networks Junos OS on SRX Series: All versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R2-S8, 19.4R3-S10; 20.2 versions prior to 20.2R3-S6; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R2.
- [Live-Hack-CVE/CVE-2023-22417](https://github.com/Live-Hack-CVE/CVE-2023-22417)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22417">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22417">

---
## CVE-2023-22416 (2023-01-13T00:15:00)
> A Buffer Overflow vulnerability in SIP ALG of Juniper Networks Junos OS allows a network-based, unauthenticated attacker to cause a Denial of Service (DoS). On all MX Series and SRX Series platform with SIP ALG enabled, when a malformed SIP packet is received, the flow processing daemon (flowd) will crash and restart. This issue affects: Juniper Networks Junos OS on MX Series and SRX Series 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3-S2; 21.3 versions prior to 21.3R3-S1; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R1-S2, 22.1R2; 22.2 versions prior to 22.2R1-S1, 22.2R2. This issue does not affect Juniper Networks Junos OS versions prior to 20.4R1 on SRX Series.
- [Live-Hack-CVE/CVE-2023-22416](https://github.com/Live-Hack-CVE/CVE-2023-22416)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22416">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22416">

---
## CVE-2023-22415 (2023-01-13T00:15:00)
> An Out-of-Bounds Write vulnerability in the H.323 ALG of Juniper Networks Junos OS allows an unauthenticated, network-based attacker to cause Denial of Service (DoS). On all MX Series and SRX Series platform, when H.323 ALG is enabled and specific H.323 packets are received simultaneously, a flow processing daemon (flowd) crash will occur. Continued receipt of these specific packets will cause a sustained Denial of Service (DoS) condition. This issue affects: Juniper Networks Junos OS on MX Series and SRX Series All versions prior to 19.4R3-S10; 20.2 versions prior to 20.2R3-S6; 20.3 versions prior to 20.3R3-S6; 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3-S3; 21.3 versions prior to 21.3R3-S3; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R2-S1, 22.1R3; 22.2 versions prior to 22.2R1-S2, 22.2R2.
- [Live-Hack-CVE/CVE-2023-22415](https://github.com/Live-Hack-CVE/CVE-2023-22415)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22415">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22415">

---
## CVE-2023-22414 (2023-01-13T00:15:00)
> A Missing Release of Memory after Effective Lifetime vulnerability in Flexible PIC Concentrator (FPC) of Juniper Networks Junos OS allows an adjacent, unauthenticated attacker from the same shared physical or logical network, to cause a heap memory leak and leading to FPC crash. On all Junos PTX Series and QFX10000 Series, when specific EVPN VXLAN Multicast packets are processed, an FPC heap memory leak is observed. The FPC memory usage can be monitored using the CLI command "show heap extensive". Following is an example output. ID Base Total(b) Free(b) Used(b) % Name Peak used % -- -------- --------- --------- --------- --- ----------- ----------- 0 37dcf000 3221225472 1694526368 1526699104 47 Kernel 47 1 17dcf000 1048576 1048576 0 0 TOE DMA 0 2 17ecf000 1048576 1048576 0 0 DMA 0 3 17fcf000 534773760 280968336 253805424 47 Packet DMA 47 This issue affects: Juniper Networks Junos OS PTX Series and QFX10000 Series 20.2 versions prior to 20.2R3-S6; 20.3 versions prior to 20.3R3-S6; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R2; 22.2 versions prior to 22.2R2. This issue does not affect Juniper Networks Junos OS versions prior to 20.1R1 on PTX Series and QFX10000 Series.
- [Live-Hack-CVE/CVE-2023-22414](https://github.com/Live-Hack-CVE/CVE-2023-22414)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22414">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22414">

---
## CVE-2023-22413 (2023-01-13T00:15:00)
> An Improper Check or Handling of Exceptional Conditions vulnerability in the IPsec library of Juniper Networks Junos OS allows a network-based, unauthenticated attacker to cause Denial of Service (DoS). On all MX platforms with MS-MPC or MS-MIC card, when specific IPv4 packets are processed by an IPsec6 tunnel, the Multiservices PIC Management Daemon (mspmand) process will core and restart. This will lead to FPC crash. Traffic flow is impacted while mspmand restarts. Continued receipt of these specific packets will cause a sustained Denial of Service (DoS) condition. This issue only occurs if an IPv4 address is not configured on the multiservice interface. This issue affects: Juniper Networks Junos OS on MX Series All versions prior to 19.4R3-S9; 20.1 version 20.1R3-S5 and later versions; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R2-S1, 21.4R3; 22.1 versions prior to 22.1R2.
- [Live-Hack-CVE/CVE-2023-22413](https://github.com/Live-Hack-CVE/CVE-2023-22413)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22413">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22413">

---
## CVE-2023-22412 (2023-01-13T00:15:00)
> An Improper Locking vulnerability in the SIP ALG of Juniper Networks Junos OS on MX Series with MS-MPC or MS-MIC card and SRX Series allows an unauthenticated, network-based attacker to cause a flow processing daemon (flowd) crash and thereby a Denial of Service (DoS). Continued receipt of these specific packets will cause a sustained Denial of Service condition. This issue occurs when SIP ALG is enabled and specific SIP messages are processed simultaneously. This issue affects: Juniper Networks Junos OS on MX Series and SRX Series 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S2; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R2. This issue does not affect Juniper Networks Junos OS versions prior to 20.4R1 on MX Series, or SRX Series.
- [Live-Hack-CVE/CVE-2023-22412](https://github.com/Live-Hack-CVE/CVE-2023-22412)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22412">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22412">

---
## CVE-2023-22411 (2023-01-13T00:15:00)
> An Out-of-Bounds Write vulnerability in Flow Processing Daemon (flowd) of Juniper Networks Junos OS allows an unauthenticated, network-based attacker to cause Denial of Service (DoS). On SRX Series devices using Unified Policies with IPv6, when a specific IPv6 packet goes through a dynamic-application filter which will generate an ICMP deny message, the flowd core is observed and the PFE is restarted. This issue affects: Juniper Networks Junos OS on SRX Series: 19.2 versions prior to 19.2R3-S6; 19.3 versions prior to 19.3R3-S6; 19.4 versions prior to 19.4R3-S9; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S4; 20.4 versions prior to 20.4R3-S3; 21.1 versions prior to 21.1R3; 21.2 versions prior to 21.2R3; 21.3 versions prior to 21.3R2; 21.4 versions prior to 21.4R2.
- [Live-Hack-CVE/CVE-2023-22411](https://github.com/Live-Hack-CVE/CVE-2023-22411)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22411">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22411">

---
## CVE-2023-22410 (2023-01-13T00:15:00)
> A Missing Release of Memory after Effective Lifetime vulnerability in the Juniper Networks Junos OS on MX Series platforms with MPC10/MPC11 line cards, allows an unauthenticated adjacent attacker to cause a Denial of Service (DoS). Devices are only vulnerable when the Suspicious Control Flow Detection (scfd) feature is enabled. Upon enabling this specific feature, an attacker sending specific traffic is causing memory to be allocated dynamically and it is not freed. Memory is not freed even after deactivating this feature. Sustained processing of such traffic will eventually lead to an out of memory condition that prevents all services from continuing to function, and requires a manual restart to recover. The FPC memory usage can be monitored using the CLI command "show chassis fpc". On running the above command, the memory of AftDdosScfdFlow can be observed to detect the memory leak. This issue affects Juniper Networks Junos OS on MX Series: All versions prior to 20.2R3-S5; 20.3 version 20.3R1 and later versions.
- [Live-Hack-CVE/CVE-2023-22410](https://github.com/Live-Hack-CVE/CVE-2023-22410)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22410">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22410">

---
## CVE-2023-22409 (2023-01-13T00:15:00)
> An Unchecked Input for Loop Condition vulnerability in a NAT library of Juniper Networks Junos OS allows a local authenticated attacker with low privileges to cause a Denial of Service (DoS). When an inconsistent "deterministic NAT" configuration is present on an SRX, or MX with SPC3 and then a specific CLI command is issued the SPC will crash and restart. Repeated execution of this command will lead to a sustained DoS. Such a configuration is characterized by the total number of port blocks being greater than the total number of hosts. An example for such configuration is: [ services nat source pool TEST-POOL address x.x.x.0/32 to x.x.x.15/32 ] [ services nat source pool TEST-POOL port deterministic block-size 1008 ] [ services nat source pool TEST-POOL port deterministic host address y.y.y.0/24] [ services nat source pool TEST-POOL port deterministic include-boundary-addresses] where according to the following calculation: 65536-1024=64512 (number of usable ports per IP address, implicit) 64512/1008=64 (number of port blocks per Nat IP) x.x.x.0/32 to x.x.x.15/32 = 16 (NAT IP addresses available in NAT pool) total port blocks in NAT Pool = 64 blocks per IP * 16 IPs = 1024 Port blocks host address y.y.y.0/24 = 256 hosts (with include-boundary-addresses) If the port block size is configured to be 4032, then the total port blocks are (64512/4032) * 16 = 256 which is equivalent to the total host addresses of 256, and the issue will not be seen. This issue affects Juniper Networks Junos OS on SRX Series, and MX Series with SPC3: All versions prior to 19.4R3-S10; 20.1 version 20.1R1 and later versions; 20.2 versions prior to 20.2R3-S6; 20.3 versions prior to 20.3R3-S6; 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3-S3; 21.3 versions prior to 21.3R3-S3; 21.4 versions prior to 21.4R3-S1; 22.1 versions prior to 22.1R2-S2, 22.1R3; 22.2 versions prior to 22.2R2.
- [Live-Hack-CVE/CVE-2023-22409](https://github.com/Live-Hack-CVE/CVE-2023-22409)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22409">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22409">

---
## CVE-2023-22408 (2023-01-13T00:15:00)
> An Improper Validation of Array Index vulnerability in the SIP ALG of Juniper Networks Junos OS on SRX 5000 Series allows a network-based, unauthenticated attacker to cause a Denial of Service (DoS). When an attacker sends an SIP packets with a malformed SDP field then the SIP ALG can not process it which will lead to an FPC crash and restart. Continued receipt of these specific packets will lead to a sustained Denial of Service. This issue can only occur when both below mentioned conditions are fulfilled: 1. Call distribution needs to be enabled: [security alg sip enable-call-distribution] 2. The SIP ALG needs to be enabled, either implicitly / by default or by way of configuration. To confirm whether SIP ALG is enabled on SRX, and MX with SPC3 use the following command: user@host> show security alg status | match sip SIP : Enabled This issue affects Juniper Networks Junos OS on SRX 5000 Series: 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3-S3; 21.3 versions prior to 21.3R3-S3; 21.4 versions prior to 21.4R3-S2; 22.1 versions prior to 22.1R2-S2, 22.1R3; 22.2 versions prior to 22.2R3; 22.3 versions prior to 22.3R1-S1, 22.3R2. This issue does not affect Juniper Networks Junos OS versions prior to 20.4R1.
- [Live-Hack-CVE/CVE-2023-22408](https://github.com/Live-Hack-CVE/CVE-2023-22408)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22408">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22408">

---
## CVE-2023-22407 (2023-01-13T00:15:00)
> An Incomplete Cleanup vulnerability in the Routing Protocol Daemon (rpd) of Juniper Networks Junos OS and Junos OS Evolved allows an adjacent, unauthenticated attacker to cause a Denial of Service (DoS). An rpd crash can occur when an MPLS TE tunnel configuration change occurs on a directly connected router. This issue affects: Juniper Networks Junos OS All versions prior to 18.4R2-S7; 19.1 versions prior to 19.1R3-S2; 19.2 versions prior to 19.2R3; 19.3 versions prior to 19.3R3; 19.4 versions prior to 19.4R3; 20.1 versions prior to 20.1R2; 20.2 versions prior to 20.2R2. Juniper Networks Junos OS Evolved All versions prior to 19.2R3-EVO; 19.3 versions prior to 19.3R3-EVO; 19.4 versions prior to 19.4R3-EVO; 20.1 versions prior to 20.1R3-EVO; 20.2 versions prior to 20.2R2-EVO.
- [Live-Hack-CVE/CVE-2023-22407](https://github.com/Live-Hack-CVE/CVE-2023-22407)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22407">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22407">

---
## CVE-2023-22406 (2023-01-13T00:15:00)
> A Missing Release of Memory after Effective Lifetime vulnerability in the kernel of Juniper Networks Junos OS and Junos OS Evolved allows an adjacent, unauthenticated attacker to cause a Denial of Service (DoS). In a segment-routing scenario with OSPF as IGP, when a peer interface continuously flaps, next-hop churn will happen and a continuous increase in Routing Protocol Daemon (rpd) memory consumption will be observed. This will eventually lead to an rpd crash and restart when the memory is full. The memory consumption can be monitored using the CLI command "show task memory detail" as shown in the following example: user@host> show task memory detail | match "RT_NEXTHOPS_TEMPLATE|RT_TEMPLATE_BOOK_KEE" RT_NEXTHOPS_TEMPLATE 1008 1024 T 50 51200 50 51200 RT_NEXTHOPS_TEMPLATE 688 768 T 50 38400 50 38400 RT_NEXTHOPS_TEMPLATE 368 384 T 412330 158334720 412330 158334720 RT_TEMPLATE_BOOK_KEE 2064 2560 T 33315 85286400 33315 85286400 user@host> show task memory detail | match "RT_NEXTHOPS_TEMPLATE|RT_TEMPLATE_BOOK_KEE" RT_NEXTHOPS_TEMPLATE 1008 1024 T 50 51200 50 51200 RT_NEXTHOPS_TEMPLATE 688 768 T 50 38400 50 38400 RT_NEXTHOPS_TEMPLATE 368 384 T 419005 160897920 419005 160897920 <=== RT_TEMPLATE_BOOK_KEE 2064 2560 T 39975 102336000 39975 10233600 <=== This issue affects: Juniper Networks Junos OS All versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R2-S8, 19.4R3-S9; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S2; 21.3 versions prior to 21.3R3-S1; 21.4 versions prior to 21.4R2-S1, 21.4R3; 22.1 versions prior to 22.1R2. Juniper Networks Junos OS Evolved All versions prior to 20.4R3-S4-EVO; 21.4 versions prior to 21.4R2-S1-EVO, 21.4R3-EVO; 22.1 versions prior to 22.1R2-EVO.
- [Live-Hack-CVE/CVE-2023-22406](https://github.com/Live-Hack-CVE/CVE-2023-22406)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22406">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22406">

---
## CVE-2023-22405 (2023-01-13T00:15:00)
> An Improper Preservation of Consistency Between Independent Representations of Shared State vulnerability in the Packet Forwarding Engine (PFE) of Juniper Networks Junos OS allows an adjacent, unauthenticated attacker to cause a Denial of Service (DoS) to device due to out of resources. When a device is configured with "service-provider/SP style" switching, and mac-limiting is configured on an Aggregated Ethernet (ae) interface, and then a PFE is restarted or the device is rebooted, mac-limiting doesn't work anymore. Please note that the issue might not be apparent as traffic will continue to flow through the device although the mac table and respective logs will indicate that mac limit is reached. Functionality can be restored by removing and re-adding the MAC limit configuration. This issue affects Juniper Networks Junos OS on QFX5k Series, EX46xx Series: All versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R3 on; 21.4 versions prior to 21.4R3 on; 22.1 versions prior to 22.1R2 on.
- [Live-Hack-CVE/CVE-2023-22405](https://github.com/Live-Hack-CVE/CVE-2023-22405)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22405">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22405">

---
## CVE-2023-22404 (2023-01-13T00:15:00)
> An Out-of-bounds Write vulnerability in the Internet Key Exchange Protocol daemon (iked) of Juniper Networks Junos OS on SRX series and MX with SPC3 allows an authenticated, network-based attacker to cause a Denial of Service (DoS). iked will crash and restart, and the tunnel will not come up when a peer sends a specifically formatted payload during the negotiation. This will impact other IKE negotiations happening at the same time. Continued receipt of this specifically formatted payload will lead to continuous crashing of iked and thereby the inability for any IKE negotiations to take place. Note that this payload is only processed after the authentication has successfully completed. So the issue can only be exploited by an attacker who can successfully authenticate. This issue affects Juniper Networks Junos OS on SRX Series, and MX Series with SPC3: All versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R3-S9; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S2; 21.3 versions prior to 21.3R3-S1; 21.4 versions prior to 21.4R2-S1, 21.4R3; 22.1 versions prior to 22.1R1-S2, 22.1R2.
- [Live-Hack-CVE/CVE-2023-22404](https://github.com/Live-Hack-CVE/CVE-2023-22404)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22404">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22404">

---
## CVE-2023-22403 (2023-01-13T00:15:00)
> An Allocation of Resources Without Limits or Throttling vulnerability in the Packet Forwarding Engine (PFE) of Juniper Networks Junos OS allows a network-based, unauthenticated attacker to cause a Denial of Service (DoS). On QFX10k Series Inter-Chassis Control Protocol (ICCP) is used in MC-LAG topologies to exchange control information between the devices in the topology. ICCP connection flaps and sync issues will be observed due to excessive specific traffic to the local device. This issue affects Juniper Networks Junos OS: All versions prior to 20.2R3-S7; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R2.
- [Live-Hack-CVE/CVE-2023-22403](https://github.com/Live-Hack-CVE/CVE-2023-22403)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22403">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22403">

---
## CVE-2023-22402 (2023-01-13T00:15:00)
> A Use After Free vulnerability in the kernel of Juniper Networks Junos OS Evolved allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS). In a Non Stop Routing (NSR) scenario, an unexpected kernel restart might be observed if "bgp auto-discovery" is enabled and if there is a BGP neighbor flap of auto-discovery sessions for any reason. This is a race condition which is outside of an attackers direct control and it depends on system internal timing whether this issue occurs. This issue affects Juniper Networks Junos OS Evolved: 21.3 versions prior to 21.3R3-EVO; 21.4 versions prior to 21.4R2-EVO; 22.1 versions prior to 22.1R2-EVO; 22.2 versions prior to 22.2R1-S1-EVO, 22.2R2-EVO.
- [Live-Hack-CVE/CVE-2023-22402](https://github.com/Live-Hack-CVE/CVE-2023-22402)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22402">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22402">

---
## CVE-2023-22401 (2023-01-13T00:15:00)
> An Improper Validation of Array Index vulnerability in the Advanced Forwarding Toolkit Manager daemon (aftmand) of Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS). On the PTX10008 and PTX10016 platforms running Junos OS or Junos OS Evolved, when a specific SNMP MIB is queried this will cause a PFE crash and the FPC will go offline and not automatically recover. A system restart is required to get the affected FPC in an operational state again. This issue affects: Juniper Networks Junos OS 22.1 version 22.1R2 and later versions; 22.1 versions prior to 22.1R3; 22.2 versions prior to 22.2R2. Juniper Networks Junos OS Evolved 21.3-EVO version 21.3R3-EVO and later versions; 21.4-EVO version 21.4R1-S2-EVO, 21.4R2-EVO and later versions prior to 21.4R2-S1-EVO; 22.1-EVO version 22.1R2-EVO and later versions prior to 22.1R3-EVO; 22.2-EVO versions prior to 22.2R1-S1-EVO, 22.2R2-EVO.
- [Live-Hack-CVE/CVE-2023-22401](https://github.com/Live-Hack-CVE/CVE-2023-22401)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22401">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22401">

---
## CVE-2023-22400 (2023-01-13T00:15:00)
> An Uncontrolled Resource Consumption vulnerability in the PFE management daemon (evo-pfemand) of Juniper Networks Junos OS Evolved allows an unauthenticated, network-based attacker to cause an FPC crash leading to a Denial of Service (DoS). When a specific SNMP GET operation or a specific CLI command is executed this will cause a GUID resource leak, eventually leading to exhaustion and result in an FPC crash and reboot. GUID exhaustion will trigger a syslog message like one of the following for example: evo-pfemand[<pid>]: get_next_guid: Ran out of Guid Space ... evo-aftmand-zx[<pid>]: get_next_guid: Ran out of Guid Space ... This leak can be monitored by running the following command and taking note of the value in the rightmost column labeled Guids: user@host> show platform application-info allocations app evo-pfemand | match "IFDId|IFLId|Context" Node Application Context Name Live Allocs Fails Guids re0 evo-pfemand net::juniper::interfaces::IFDId 0 3448 0 3448 re0 evo-pfemand net::juniper::interfaces::IFLId 0 561 0 561 user@host> show platform application-info allocations app evo-pfemand | match "IFDId|IFLId|Context" Node Application Context Name Live Allocs Fails Guids re0 evo-pfemand net::juniper::interfaces::IFDId 0 3784 0 3784 re0 evo-pfemand net::juniper::interfaces::IFLId 0 647 0 647 This issue affects Juniper Networks Junos OS Evolved: All versions prior to 20.4R3-S3-EVO; 21.1-EVO version 21.1R1-EVO and later versions; 21.2-EVO versions prior to 21.2R3-S4-EVO; 21.3-EVO version 21.3R1-EVO and later versions; 21.4-EVO versions prior to 21.4R2-EVO.
- [Live-Hack-CVE/CVE-2023-22400](https://github.com/Live-Hack-CVE/CVE-2023-22400)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22400">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22400">

---
## CVE-2023-22399 (2023-01-13T00:15:00)
> When sFlow is enabled and it monitors a packet forwarded via ECMP, a buffer management vulnerability in the dcpfe process of Juniper Networks Junos OS on QFX10K Series systems allows an attacker to cause the Packet Forwarding Engine (PFE) to crash and restart by sending specific genuine packets to the device, resulting in a Denial of Service (DoS) condition. The dcpfe process tries to copy more data into a smaller buffer, which overflows and corrupts the buffer, causing a crash of the dcpfe process. Continued receipt and processing of these packets will create a sustained Denial of Service (DoS) condition. This issue affects Juniper Networks Junos OS on QFX10K Series: All versions prior to 19.4R3-S9; 20.2 versions prior to 20.2R3-S6; 20.3 versions prior to 20.3R3-S6; 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3-S3; 21.3 versions prior to 21.3R3-S2; 21.4 versions prior to 21.4R2-S2, 21.4R3; 22.1 versions prior to 22.1R2; 22.2 versions prior to 22.2R1-S2, 22.2R2.
- [Live-Hack-CVE/CVE-2023-22399](https://github.com/Live-Hack-CVE/CVE-2023-22399)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22399">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22399">

---
## CVE-2023-22397 (2023-01-13T00:15:00)
> An Allocation of Resources Without Limits or Throttling weakness in the memory management of the Packet Forwarding Engine (PFE) on Juniper Networks Junos OS Evolved PTX10003 Series devices allows an adjacently located attacker who has established certain preconditions and knowledge of the environment to send certain specific genuine packets to begin a Time-of-check Time-of-use (TOCTOU) Race Condition attack which will cause a memory leak to begin. Once this condition begins, and as long as the attacker is able to sustain the offending traffic, a Distributed Denial of Service (DDoS) event occurs. As a DDoS event, the offending packets sent by the attacker will continue to flow from one device to another as long as they are received and processed by any devices, ultimately causing a cascading outage to any vulnerable devices. Devices not vulnerable to the memory leak will process and forward the offending packet(s) to neighboring devices. Due to internal anti-flood security controls and mechanisms reaching their maximum limit of response in the worst-case scenario, all affected Junos OS Evolved devices will reboot in as little as 1.5 days. Reboots to restore services cannot be avoided once the memory leak begins. The device will self-recover after crashing and rebooting. Operator intervention isn't required to restart the device. This issue affects: Juniper Networks Junos OS Evolved on PTX10003: All versions prior to 20.4R3-S4-EVO; 21.3 versions prior to 21.3R3-S1-EVO; 21.4 versions prior to 21.4R2-S2-EVO, 21.4R3-EVO; 22.1 versions prior to 22.1R1-S2-EVO, 22.1R2-EVO; 22.2 versions prior to 22.2R2-EVO. To check memory, customers may VTY to the PFE first then execute the following show statement: show jexpr jtm ingress-main-memory chip 255 | no-more Alternatively one may execute from the RE CLI: request pfe execute target fpc0 command "show jexpr jtm ingress-main-memory chip 255 | no-more" Iteration 1: Example output: Mem type: NH, alloc type: JTM 136776 bytes used (max 138216 bytes used) 911568 bytes available (909312 bytes from free pages) Iteration 2: Example output: Mem type: NH, alloc type: JTM 137288 bytes used (max 138216 bytes used) 911056 bytes available (909312 bytes from free pages) The same can be seen in the CLI below, assuming the scale does not change: show npu memory info Example output: FPC0:NPU16 mem-util-jnh-nh-size 2097152 FPC0:NPU16 mem-util-jnh-nh-allocated 135272 FPC0:NPU16 mem-util-jnh-nh-utilization 6
- [Live-Hack-CVE/CVE-2023-22397](https://github.com/Live-Hack-CVE/CVE-2023-22397)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22397">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22397">

---
## CVE-2023-22395 (2023-01-13T00:15:00)
> A Missing Release of Memory after Effective Lifetime vulnerability in the kernel of Juniper Networks Junos OS allows an unauthenticated, adjacent attacker to cause a Denial of Service (DoS). In an MPLS scenario specific packets destined to an Integrated Routing and Bridging (irb) interface of the device will cause a buffer (mbuf) to leak. Continued receipt of these specific packets will eventually cause a loss of connectivity to and from the device, and requires a reboot to recover. These mbufs can be monitored by using the CLI command 'show system buffers': user@host> show system buffers 783/1497/2280 mbufs in use (current/cache/total) user@host> show system buffers 793/1487/2280 mbufs in use (current/cache/total) <<<<<< mbuf usage increased This issue affects Juniper Networks Junos OS: All versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R3-S9; 20.1 version 20.1R1 and later versions; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S2; 21.3 versions prior to 21.3R3-S1; 21.4 versions prior to 21.4R3; 22.1 versions prior to 22.1R2.
- [Live-Hack-CVE/CVE-2023-22395](https://github.com/Live-Hack-CVE/CVE-2023-22395)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22395">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22395">

---
## CVE-2023-22373 (2023-01-20T03:15:00)
> Cross-site scripting vulnerability in CONPROSYS HMI System (CHS) Ver.3.4.5 and earlier allows a remote authenticated attacker to inject an arbitrary script and obtain the sensitive information.
- [Live-Hack-CVE/CVE-2023-22373](https://github.com/Live-Hack-CVE/CVE-2023-22373)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22373">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22373">

---
## CVE-2023-22366 (2023-01-17T10:15:00)
> CX-Motion-MCH v2.32 and earlier contains an access of uninitialized pointer vulnerability. Having a user to open a specially crafted project file may lead to information disclosure and/or arbitrary code execution.
- [Live-Hack-CVE/CVE-2023-22366](https://github.com/Live-Hack-CVE/CVE-2023-22366)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22366">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22366">

---
## CVE-2023-22357 (2023-01-17T10:15:00)
> Active debug code exists in OMRON CP1L-EL20DR-D all versions, which may lead to a command that is not specified in FINS protocol being executed without authentication. A remote unauthenticated attacker may read/write in arbitrary area of the device memory, which may lead to overwriting the firmware, causing a denial-of-service (DoS) condition, and/or arbitrary code execution.
- [Live-Hack-CVE/CVE-2023-22357](https://github.com/Live-Hack-CVE/CVE-2023-22357)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22357">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22357">

---
## CVE-2023-22339 (2023-01-20T03:15:00)
> Improper access control vulnerability in CONPROSYS HMI System (CHS) Ver.3.4.5 and earlier allows a remote unauthenticated attacker to bypass access restriction and obtain the server certificate including the private key of the product.
- [Live-Hack-CVE/CVE-2023-22339](https://github.com/Live-Hack-CVE/CVE-2023-22339)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22339">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22339">

---
## CVE-2023-22334 (2023-01-20T03:15:00)
> Use of password hash instead of password for authentication vulnerability in CONPROSYS HMI System (CHS) Ver.3.4.5 and earlier allows a remote authenticated attacker to obtain user credentials information via a man-in-the-middle attack.
- [Live-Hack-CVE/CVE-2023-22334](https://github.com/Live-Hack-CVE/CVE-2023-22334)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22334">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22334">

---
## CVE-2023-22331 (2023-01-20T03:15:00)
> Use of default credentials vulnerability in CONPROSYS HMI System (CHS) Ver.3.4.5 and earlier allows a remote unauthenticated attacker to alter user credentials information.
- [Live-Hack-CVE/CVE-2023-22331](https://github.com/Live-Hack-CVE/CVE-2023-22331)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22331">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22331">

---
## CVE-2023-22320 (2023-01-10T04:15:00)
> OpenAM Web Policy Agent (OpenAM Consortium Edition) provided by OpenAM Consortium parses URLs improperly, leading to a path traversal vulnerability(CWE-22). Furthermore, a crafted URL may be evaluated incorrectly.
- [Live-Hack-CVE/CVE-2023-22320](https://github.com/Live-Hack-CVE/CVE-2023-22320)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22320">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22320">

---
## CVE-2023-22316 (2023-01-17T10:15:00)
> Hidden functionality vulnerability in PIX-RT100 versions RT100_TEQ_2.1.1_EQ101 and RT100_TEQ_2.1.2_EQ101 allows a network-adjacent attacker to access the product via undocumented Telnet or SSH services.
- [Live-Hack-CVE/CVE-2023-22316](https://github.com/Live-Hack-CVE/CVE-2023-22316)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22316">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22316">

---
## CVE-2023-22304 (2023-01-17T10:15:00)
> OS command injection vulnerability in PIX-RT100 versions RT100_TEQ_2.1.1_EQ101 and RT100_TEQ_2.1.2_EQ101 allows a network-adjacent attacker who can access product settings to execute an arbitrary OS command.
- [Live-Hack-CVE/CVE-2023-22304](https://github.com/Live-Hack-CVE/CVE-2023-22304)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22304">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22304">

---
## CVE-2023-22303 (2023-01-17T10:15:00)
> TP-Link SG105PE firmware prior to 'TL-SG105PE(UN) 1.0_1.0.0 Build 20221208' contains an authentication bypass vulnerability. Under the certain conditions, an attacker may impersonate an administrator of the product. As a result, information may be obtained and/or the product's settings may be altered with the privilege of the administrator.
- [Live-Hack-CVE/CVE-2023-22303](https://github.com/Live-Hack-CVE/CVE-2023-22303)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22303">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22303">

---
## CVE-2023-22298 (2023-01-17T10:15:00)
> Open redirect vulnerability in pgAdmin 4 versions prior to v6.14 allows a remote unauthenticated attacker to redirect a user to an arbitrary web site and conduct a phishing attack by having a user to access a specially crafted URL.
- [Live-Hack-CVE/CVE-2023-22298](https://github.com/Live-Hack-CVE/CVE-2023-22298)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22298">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22298">

---
## CVE-2023-22296 (2023-01-17T10:15:00)
> Reflected cross-site scripting vulnerability in MAHO-PBX NetDevancer series MAHO-PBX NetDevancer Lite/Uni/Pro/Cloud prior to Ver.1.11.00, MAHO-PBX NetDevancer VSG Lite/Uni prior to Ver.1.11.00, and MAHO-PBX NetDevancer MobileGate Home/Office prior to Ver.1.11.00 allows a remote unauthenticated attacker to inject an arbitrary script.
- [Live-Hack-CVE/CVE-2023-22296](https://github.com/Live-Hack-CVE/CVE-2023-22296)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22296">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22296">

---
## CVE-2023-22286 (2023-01-17T10:15:00)
> Cross-site request forgery (CSRF) vulnerability in MAHO-PBX NetDevancer Lite/Uni/Pro/Cloud prior to Ver.1.11.00, MAHO-PBX NetDevancer VSG Lite/Uni prior to Ver.1.11.00, and MAHO-PBX NetDevancer MobileGate Home/Office prior to Ver.1.11.00 allows a remote unauthenticated attacker to hijack the user authentication and conduct user's unintended operations by having a user to view a malicious page while logged in.
- [Live-Hack-CVE/CVE-2023-22286](https://github.com/Live-Hack-CVE/CVE-2023-22286)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22286">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22286">

---
## CVE-2023-22280 (2023-01-17T10:15:00)
> MAHO-PBX NetDevancer Lite/Uni/Pro/Cloud prior to Ver.1.11.00, MAHO-PBX NetDevancer VSG Lite/Uni prior to Ver.1.11.00, and MAHO-PBX NetDevancer MobileGate Home/Office prior to Ver.1.11.00 allow a remote authenticated attacker with an administrative privilege to execute an arbitrary OS command.
- [Live-Hack-CVE/CVE-2023-22280](https://github.com/Live-Hack-CVE/CVE-2023-22280)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22280">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22280">

---
## CVE-2023-22279 (2023-01-17T10:15:00)
> MAHO-PBX NetDevancer Lite/Uni/Pro/Cloud prior to Ver.1.11.00, MAHO-PBX NetDevancer VSG Lite/Uni prior to Ver.1.11.00, and MAHO-PBX NetDevancer MobileGate Home/Office prior to Ver.1.11.00 allow a remote unauthenticated attacker to execute an arbitrary OS command.
- [Live-Hack-CVE/CVE-2023-22279](https://github.com/Live-Hack-CVE/CVE-2023-22279)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22279">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22279">

---
## CVE-2023-22278 (2023-01-17T10:15:00)
> m-FILTER prior to Ver.5.70R01 (Ver.5 Series) and m-FILTER prior to Ver.4.87R04 (Ver.4 Series) allows a remote unauthenticated attacker to bypass authentication and send users' unintended email when email is being sent under the certain conditions. The attacks exploiting this vulnerability have been observed.
- [Live-Hack-CVE/CVE-2023-22278](https://github.com/Live-Hack-CVE/CVE-2023-22278)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22278">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22278">

---
## CVE-2023-21891 (2023-01-18T00:15:00)
> Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Fusion Middleware (component: Visual Analyzer).  Supported versions that are affected are 5.9.0.0.0 and  6.4.0.0.0. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Business Intelligence Enterprise Edition.  Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Business Intelligence Enterprise Edition, attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability can result in  unauthorized update, insert or delete access to some of Oracle Business Intelligence Enterprise Edition accessible data as well as  unauthorized read access to a subset of Oracle Business Intelligence Enterprise Edition accessible data. CVSS 3.1 Base Score 5.4 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N).
- [Live-Hack-CVE/CVE-2023-21891](https://github.com/Live-Hack-CVE/CVE-2023-21891)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21891">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21891">

---
## CVE-2023-21864 (2023-01-18T00:15:00)
> Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer).  Supported versions that are affected are 8.0.30 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
- [Live-Hack-CVE/CVE-2023-21864](https://github.com/Live-Hack-CVE/CVE-2023-21864)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21864">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21864">

---
## CVE-2023-21853 (2023-01-18T00:15:00)
> Vulnerability in the Oracle Mobile Field Service product of Oracle E-Business Suite (component: Synchronization).  Supported versions that are affected are 12.2.3-12.2.12. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Mobile Field Service.  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle Mobile Field Service accessible data. CVSS 3.1 Base Score 7.5 (Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N).
- [Live-Hack-CVE/CVE-2023-21853](https://github.com/Live-Hack-CVE/CVE-2023-21853)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21853">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21853">

---
## CVE-2023-21850 (2023-01-18T00:15:00)
> Vulnerability in the Oracle Demantra Demand Management product of Oracle Supply Chain (component: E-Business Collections).  Supported versions that are affected are 12.1 and  12.2. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Demantra Demand Management.  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle Demantra Demand Management accessible data. CVSS 3.1 Base Score 7.5 (Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N).
- [Live-Hack-CVE/CVE-2023-21850](https://github.com/Live-Hack-CVE/CVE-2023-21850)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21850">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21850">

---
## CVE-2023-21849 (2023-01-18T00:15:00)
> Vulnerability in the Oracle Applications DBA product of Oracle E-Business Suite (component: Java utils).  Supported versions that are affected are 12.2.3-12.2.12. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Applications DBA.  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle Applications DBA accessible data. CVSS 3.1 Base Score 7.5 (Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N).
- [Live-Hack-CVE/CVE-2023-21849](https://github.com/Live-Hack-CVE/CVE-2023-21849)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21849">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21849">

---
## CVE-2023-21847 (2023-01-18T00:15:00)
> Vulnerability in the Oracle Web Applications Desktop Integrator product of Oracle E-Business Suite (component: Download).  Supported versions that are affected are 12.2.3-12.2.12. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Web Applications Desktop Integrator.  Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Oracle Web Applications Desktop Integrator, attacks may significantly impact additional products (scope change). Successful attacks of this vulnerability can result in  unauthorized update, insert or delete access to some of Oracle Web Applications Desktop Integrator accessible data as well as  unauthorized read access to a subset of Oracle Web Applications Desktop Integrator accessible data. CVSS 3.1 Base Score 5.4 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N).
- [Live-Hack-CVE/CVE-2023-21847](https://github.com/Live-Hack-CVE/CVE-2023-21847)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21847">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21847">

---
## CVE-2023-21846 (2023-01-18T00:15:00)
> Vulnerability in the Oracle BI Publisher product of Oracle Fusion Middleware (component: Security).  Supported versions that are affected are 5.9.0.0.0, 6.4.0.0.0 and  12.2.1.4.0. Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols to compromise Oracle BI Publisher.  Successful attacks of this vulnerability can result in takeover of Oracle BI Publisher. CVSS 3.1 Base Score 8.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H).
- [Live-Hack-CVE/CVE-2023-21846](https://github.com/Live-Hack-CVE/CVE-2023-21846)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21846">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21846">

---
## CVE-2023-21843 (2023-01-18T00:15:00)
> Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Sound).  Supported versions that are affected are Oracle Java SE: 8u351, 8u351-perf, 11.0.17, 17.0.5, 19.0.1; Oracle GraalVM Enterprise Edition: 20.3.8, 21.3.4 and  22.3.0. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in  unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 3.7 (Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N).
- [Live-Hack-CVE/CVE-2023-21843](https://github.com/Live-Hack-CVE/CVE-2023-21843)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21843">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21843">

---
## CVE-2023-21841 (2023-01-18T00:15:00)
> Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and  14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).
- [Live-Hack-CVE/CVE-2023-21841](https://github.com/Live-Hack-CVE/CVE-2023-21841)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21841">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21841">

---
## CVE-2023-21840 (2023-01-18T00:15:00)
> Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: PS).  Supported versions that are affected are 5.7.40 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
- [Live-Hack-CVE/CVE-2023-21840](https://github.com/Live-Hack-CVE/CVE-2023-21840)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21840">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21840">

---
## CVE-2023-21839 (2023-01-18T00:15:00)
> Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and  14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via T3, IIOP to compromise Oracle WebLogic Server.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).
- [Live-Hack-CVE/CVE-2023-21839](https://github.com/Live-Hack-CVE/CVE-2023-21839)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21839">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21839">

---
## CVE-2023-21837 (2023-01-18T00:15:00)
> Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Core).  Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and  14.1.1.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via IIOP to compromise Oracle WebLogic Server.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle WebLogic Server accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).
- [Live-Hack-CVE/CVE-2023-21837](https://github.com/Live-Hack-CVE/CVE-2023-21837)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21837">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21837">

---
## CVE-2023-21835 (2023-01-18T00:15:00)
> Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JSSE).  Supported versions that are affected are Oracle Java SE: 11.0.17, 17.0.5, 19.0.1; Oracle GraalVM Enterprise Edition: 20.3.8, 21.3.4 and  22.3.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via DTLS to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 5.3 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L).
- [Live-Hack-CVE/CVE-2023-21835](https://github.com/Live-Hack-CVE/CVE-2023-21835)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21835">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21835">

---
## CVE-2023-21832 (2023-01-18T00:15:00)
> Vulnerability in the Oracle BI Publisher product of Oracle Fusion Middleware (component: Security).  Supported versions that are affected are 5.9.0.0.0, 6.4.0.0.0 and  12.2.1.4.0. Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols to compromise Oracle BI Publisher.  Successful attacks of this vulnerability can result in takeover of Oracle BI Publisher. CVSS 3.1 Base Score 8.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H).
- [Live-Hack-CVE/CVE-2023-21832](https://github.com/Live-Hack-CVE/CVE-2023-21832)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21832">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21832">

---
## CVE-2023-21830 (2023-01-18T00:15:00)
> Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Serialization).  Supported versions that are affected are Oracle Java SE: 8u351, 8u351-perf; Oracle GraalVM Enterprise Edition: 20.3.8 and  21.3.4. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in  unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 5.3 (Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N).
- [Live-Hack-CVE/CVE-2023-21830](https://github.com/Live-Hack-CVE/CVE-2023-21830)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21830">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21830">

---
## CVE-2023-21829 (2023-01-18T00:15:00)
> Vulnerability in the Oracle Database RDBMS Security component of Oracle Database Server.  Supported versions that are affected are 19c and  21c. Easily exploitable vulnerability allows low privileged attacker having Create Session privilege with network access via Oracle Net to compromise Oracle Database RDBMS Security.  Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle Database RDBMS Security accessible data as well as  unauthorized read access to a subset of Oracle Database RDBMS Security accessible data. CVSS 3.1 Base Score 6.3 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:H/A:N).
- [Live-Hack-CVE/CVE-2023-21829](https://github.com/Live-Hack-CVE/CVE-2023-21829)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21829">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21829">

---
## CVE-2023-21827 (2023-01-18T00:15:00)
> Vulnerability in the Oracle Database Data Redaction component of Oracle Database Server.  Supported versions that are affected are 19c and  21c. Easily exploitable vulnerability allows low privileged attacker having Create Session privilege with network access via Oracle Net to compromise Oracle Database Data Redaction.  Successful attacks of this vulnerability can result in  unauthorized read access to a subset of Oracle Database Data Redaction accessible data. CVSS 3.1 Base Score 4.3 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N).
- [Live-Hack-CVE/CVE-2023-21827](https://github.com/Live-Hack-CVE/CVE-2023-21827)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21827">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21827">

---
## CVE-2023-21825 (2023-01-18T00:15:00)
> Vulnerability in the Oracle iSupplier Portal product of Oracle E-Business Suite (component: Supplier Management).  Supported versions that are affected are 12.2.6-12.2.8. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle iSupplier Portal.  Successful attacks of this vulnerability can result in  unauthorized read access to a subset of Oracle iSupplier Portal accessible data. CVSS 3.1 Base Score 5.3 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N).
- [Live-Hack-CVE/CVE-2023-21825](https://github.com/Live-Hack-CVE/CVE-2023-21825)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21825">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21825">

---
## CVE-2023-21793 (2023-01-10T22:15:00)
> 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792.
- [Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793">
- [Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792">
- [Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791">
- [Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786">
- [Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784">
- [Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783">
- [Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790">
- [Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789">
- [Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788">
- [Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787">
- [Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785">
- [Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782">
- [Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780">
- [Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781">

---
## CVE-2023-21792 (2023-01-10T22:15:00)
> 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21793.
- [Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792">
- [Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793">
- [Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791">
- [Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786">
- [Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784">
- [Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783">
- [Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790">
- [Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789">
- [Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788">
- [Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787">
- [Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785">
- [Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782">
- [Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780">
- [Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781">

---
## CVE-2023-21791 (2023-01-10T22:15:00)
> 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21792, CVE-2023-21793.
- [Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791">
- [Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793">
- [Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792">
- [Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786">
- [Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784">
- [Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783">
- [Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790">
- [Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789">
- [Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788">
- [Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787">
- [Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785">
- [Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782">
- [Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780">
- [Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781">

---
## CVE-2023-21790 (2023-01-10T22:15:00)
> 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.
- [Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790">
- [Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793">
- [Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792">
- [Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791">
- [Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786">
- [Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784">
- [Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783">
- [Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789">
- [Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788">
- [Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787">
- [Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785">
- [Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782">
- [Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780">
- [Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781">

---
## CVE-2023-21789 (2023-01-10T22:15:00)
> 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.
- [Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789">
- [Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793">
- [Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792">
- [Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791">
- [Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786">
- [Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784">
- [Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783">
- [Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790">
- [Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788">
- [Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787">
- [Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785">
- [Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782">
- [Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780">
- [Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781">

---
## CVE-2023-21788 (2023-01-10T22:15:00)
> 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.
- [Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788">
- [Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793">
- [Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792">
- [Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791">
- [Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786">
- [Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784">
- [Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783">
- [Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790">
- [Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789">
- [Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787">
- [Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785">
- [Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782">
- [Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780">
- [Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781">

---
## CVE-2023-21787 (2023-01-10T22:15:00)
> 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.
- [Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787">
- [Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793">
- [Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792">
- [Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791">
- [Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786">
- [Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784">
- [Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783">
- [Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790">
- [Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789">
- [Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788">
- [Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785">
- [Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782">
- [Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780">
- [Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781">

---
## CVE-2023-21786 (2023-01-10T22:15:00)
> 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.
- [Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786">
- [Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793">
- [Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792">
- [Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791">
- [Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784">
- [Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783">
- [Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790">
- [Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789">
- [Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788">
- [Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787">
- [Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785">
- [Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782">
- [Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780">
- [Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781">

---
## CVE-2023-21785 (2023-01-10T22:15:00)
> 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.
- [Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785">
- [Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793">
- [Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792">
- [Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791">
- [Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786">
- [Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784">
- [Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783">
- [Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790">
- [Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789">
- [Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788">
- [Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787">
- [Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782">
- [Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780">
- [Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781">

---
## CVE-2023-21784 (2023-01-10T22:15:00)
> 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.
- [Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784">
- [Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793">
- [Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792">
- [Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791">
- [Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786">
- [Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783">
- [Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790">
- [Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789">
- [Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788">
- [Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787">
- [Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785">
- [Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782">
- [Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780">
- [Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781">

---
## CVE-2023-21783 (2023-01-10T22:15:00)
> 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21782, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.
- [Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783">
- [Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793">
- [Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792">
- [Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791">
- [Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786">
- [Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784">
- [Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790">
- [Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789">
- [Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788">
- [Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787">
- [Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785">
- [Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782">
- [Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780">
- [Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781">

---
## CVE-2023-21782 (2023-01-10T22:15:00)
> 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21781, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.
- [Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782">
- [Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793">
- [Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792">
- [Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791">
- [Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786">
- [Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784">
- [Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783">
- [Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790">
- [Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789">
- [Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788">
- [Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787">
- [Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785">
- [Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780">
- [Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781">

---
## CVE-2023-21781 (2023-01-10T22:15:00)
> 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21780, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.
- [Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781">
- [Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793">
- [Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792">
- [Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791">
- [Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786">
- [Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784">
- [Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783">
- [Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790">
- [Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789">
- [Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788">
- [Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787">
- [Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785">
- [Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782">
- [Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780">

---
## CVE-2023-21780 (2023-01-10T22:15:00)
> 3D Builder Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21781, CVE-2023-21782, CVE-2023-21783, CVE-2023-21784, CVE-2023-21785, CVE-2023-21786, CVE-2023-21787, CVE-2023-21788, CVE-2023-21789, CVE-2023-21790, CVE-2023-21791, CVE-2023-21792, CVE-2023-21793.
- [Live-Hack-CVE/CVE-2023-21780](https://github.com/Live-Hack-CVE/CVE-2023-21780)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21780">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21780">
- [Live-Hack-CVE/CVE-2023-21793](https://github.com/Live-Hack-CVE/CVE-2023-21793)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21793">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21793">
- [Live-Hack-CVE/CVE-2023-21792](https://github.com/Live-Hack-CVE/CVE-2023-21792)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21792">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21792">
- [Live-Hack-CVE/CVE-2023-21791](https://github.com/Live-Hack-CVE/CVE-2023-21791)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21791">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21791">
- [Live-Hack-CVE/CVE-2023-21786](https://github.com/Live-Hack-CVE/CVE-2023-21786)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21786">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21786">
- [Live-Hack-CVE/CVE-2023-21784](https://github.com/Live-Hack-CVE/CVE-2023-21784)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21784">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21784">
- [Live-Hack-CVE/CVE-2023-21783](https://github.com/Live-Hack-CVE/CVE-2023-21783)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21783">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21783">
- [Live-Hack-CVE/CVE-2023-21790](https://github.com/Live-Hack-CVE/CVE-2023-21790)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21790">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21790">
- [Live-Hack-CVE/CVE-2023-21789](https://github.com/Live-Hack-CVE/CVE-2023-21789)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21789">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21789">
- [Live-Hack-CVE/CVE-2023-21788](https://github.com/Live-Hack-CVE/CVE-2023-21788)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21788">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21788">
- [Live-Hack-CVE/CVE-2023-21787](https://github.com/Live-Hack-CVE/CVE-2023-21787)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21787">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21787">
- [Live-Hack-CVE/CVE-2023-21785](https://github.com/Live-Hack-CVE/CVE-2023-21785)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21785">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21785">
- [Live-Hack-CVE/CVE-2023-21782](https://github.com/Live-Hack-CVE/CVE-2023-21782)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21782">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21782">
- [Live-Hack-CVE/CVE-2023-21781](https://github.com/Live-Hack-CVE/CVE-2023-21781)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21781">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21781">

---
## CVE-2023-21776 (2023-01-10T22:15:00)
> Windows Kernel Information Disclosure Vulnerability.
- [Live-Hack-CVE/CVE-2023-21776](https://github.com/Live-Hack-CVE/CVE-2023-21776)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21776">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21776">

---
## CVE-2023-21774 (2023-01-10T22:15:00)
> Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21747, CVE-2023-21748, CVE-2023-21749, CVE-2023-21750, CVE-2023-21754, CVE-2023-21755, CVE-2023-21772, CVE-2023-21773.
- [Live-Hack-CVE/CVE-2023-21774](https://github.com/Live-Hack-CVE/CVE-2023-21774)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21774">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21774">
- [Live-Hack-CVE/CVE-2023-21747](https://github.com/Live-Hack-CVE/CVE-2023-21747)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21747">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21747">
- [Live-Hack-CVE/CVE-2023-21749](https://github.com/Live-Hack-CVE/CVE-2023-21749)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21749">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21749">
- [Live-Hack-CVE/CVE-2023-21750](https://github.com/Live-Hack-CVE/CVE-2023-21750)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21750">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21750">
- [Live-Hack-CVE/CVE-2023-21748](https://github.com/Live-Hack-CVE/CVE-2023-21748)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21748">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21748">
- [Live-Hack-CVE/CVE-2023-21754](https://github.com/Live-Hack-CVE/CVE-2023-21754)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21754">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21754">
- [Live-Hack-CVE/CVE-2023-21773](https://github.com/Live-Hack-CVE/CVE-2023-21773)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21773">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21773">
- [Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772">
- [Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675">
- [Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755">

---
## CVE-2023-21773 (2023-01-10T22:15:00)
> Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21747, CVE-2023-21748, CVE-2023-21749, CVE-2023-21750, CVE-2023-21754, CVE-2023-21755, CVE-2023-21772, CVE-2023-21774.
- [Live-Hack-CVE/CVE-2023-21773](https://github.com/Live-Hack-CVE/CVE-2023-21773)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21773">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21773">
- [Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772">
- [Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675">
- [Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755">

---
## CVE-2023-21772 (2023-01-10T22:15:00)
> Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21747, CVE-2023-21748, CVE-2023-21749, CVE-2023-21750, CVE-2023-21754, CVE-2023-21755, CVE-2023-21773, CVE-2023-21774.
- [Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772">
- [Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675">
- [Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755">

---
## CVE-2023-21771 (2023-01-10T22:15:00)
> Windows Local Session Manager (LSM) Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21771](https://github.com/Live-Hack-CVE/CVE-2023-21771)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21771">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21771">

---
## CVE-2023-21768 (2023-01-10T22:15:00)
> Windows Ancillary Function Driver for WinSock Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21768](https://github.com/Live-Hack-CVE/CVE-2023-21768)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21768">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21768">

---
## CVE-2023-21767 (2023-01-10T22:15:00)
> Windows Overlay Filter Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21767](https://github.com/Live-Hack-CVE/CVE-2023-21767)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21767">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21767">

---
## CVE-2023-21766 (2023-01-10T22:15:00)
> Windows Overlay Filter Information Disclosure Vulnerability.
- [Live-Hack-CVE/CVE-2023-21766](https://github.com/Live-Hack-CVE/CVE-2023-21766)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21766">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21766">

---
## CVE-2023-21765 (2023-01-10T22:15:00)
> Windows Print Spooler Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21678, CVE-2023-21760.
- [Live-Hack-CVE/CVE-2023-21765](https://github.com/Live-Hack-CVE/CVE-2023-21765)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21765">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21765">

---
## CVE-2023-21764 (2023-01-10T22:15:00)
> Microsoft Exchange Server Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21763.
- [Live-Hack-CVE/CVE-2023-21764](https://github.com/Live-Hack-CVE/CVE-2023-21764)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21764">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21764">

---
## CVE-2023-21763 (2023-01-10T22:15:00)
> Microsoft Exchange Server Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21764.
- [Live-Hack-CVE/CVE-2023-21763](https://github.com/Live-Hack-CVE/CVE-2023-21763)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21763">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21763">
- [Live-Hack-CVE/CVE-2023-21764](https://github.com/Live-Hack-CVE/CVE-2023-21764)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21764">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21764">

---
## CVE-2023-21762 (2023-01-10T22:15:00)
> Microsoft Exchange Server Spoofing Vulnerability. This CVE ID is unique from CVE-2023-21745.
- [Live-Hack-CVE/CVE-2023-21762](https://github.com/Live-Hack-CVE/CVE-2023-21762)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21762">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21762">
- [Live-Hack-CVE/CVE-2023-21745](https://github.com/Live-Hack-CVE/CVE-2023-21745)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21745">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21745">

---
## CVE-2023-21761 (2023-01-10T22:15:00)
> Microsoft Exchange Server Information Disclosure Vulnerability.
- [Live-Hack-CVE/CVE-2023-21761](https://github.com/Live-Hack-CVE/CVE-2023-21761)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21761">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21761">

---
## CVE-2023-21760 (2023-01-10T22:15:00)
> Windows Print Spooler Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21678, CVE-2023-21765.
- [Live-Hack-CVE/CVE-2023-21760](https://github.com/Live-Hack-CVE/CVE-2023-21760)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21760">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21760">
- [Live-Hack-CVE/CVE-2023-21678](https://github.com/Live-Hack-CVE/CVE-2023-21678)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21678">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21678">
- [Live-Hack-CVE/CVE-2023-21765](https://github.com/Live-Hack-CVE/CVE-2023-21765)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21765">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21765">

---
## CVE-2023-21759 (2023-01-10T22:15:00)
> Windows Smart Card Resource Management Server Security Feature Bypass Vulnerability.
- [Live-Hack-CVE/CVE-2023-21759](https://github.com/Live-Hack-CVE/CVE-2023-21759)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21759">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21759">

---
## CVE-2023-21758 (2023-01-10T22:15:00)
> Windows Internet Key Exchange (IKE) Extension Denial of Service Vulnerability. This CVE ID is unique from CVE-2023-21677, CVE-2023-21683.
- [Live-Hack-CVE/CVE-2023-21758](https://github.com/Live-Hack-CVE/CVE-2023-21758)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21758">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21758">
- [Live-Hack-CVE/CVE-2023-21683](https://github.com/Live-Hack-CVE/CVE-2023-21683)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21683">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21683">
- [Live-Hack-CVE/CVE-2023-21677](https://github.com/Live-Hack-CVE/CVE-2023-21677)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21677">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21677">

---
## CVE-2023-21757 (2023-01-10T22:15:00)
> Windows Layer 2 Tunneling Protocol (L2TP) Denial of Service Vulnerability.
- [Live-Hack-CVE/CVE-2023-21757](https://github.com/Live-Hack-CVE/CVE-2023-21757)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21757">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21757">

---
## CVE-2023-21755 (2023-01-10T22:15:00)
> Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21747, CVE-2023-21748, CVE-2023-21749, CVE-2023-21750, CVE-2023-21754, CVE-2023-21772, CVE-2023-21773, CVE-2023-21774.
- [Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755">

---
## CVE-2023-21754 (2023-01-10T22:15:00)
> Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21747, CVE-2023-21748, CVE-2023-21749, CVE-2023-21750, CVE-2023-21755, CVE-2023-21772, CVE-2023-21773, CVE-2023-21774.
- [Live-Hack-CVE/CVE-2023-21754](https://github.com/Live-Hack-CVE/CVE-2023-21754)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21754">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21754">
- [Live-Hack-CVE/CVE-2023-21747](https://github.com/Live-Hack-CVE/CVE-2023-21747)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21747">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21747">
- [Live-Hack-CVE/CVE-2023-21749](https://github.com/Live-Hack-CVE/CVE-2023-21749)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21749">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21749">
- [Live-Hack-CVE/CVE-2023-21750](https://github.com/Live-Hack-CVE/CVE-2023-21750)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21750">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21750">
- [Live-Hack-CVE/CVE-2023-21748](https://github.com/Live-Hack-CVE/CVE-2023-21748)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21748">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21748">
- [Live-Hack-CVE/CVE-2023-21773](https://github.com/Live-Hack-CVE/CVE-2023-21773)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21773">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21773">
- [Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772">
- [Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675">
- [Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755">

---
## CVE-2023-21753 (2023-01-10T22:15:00)
> Event Tracing for Windows Information Disclosure Vulnerability. This CVE ID is unique from CVE-2023-21536.
- [Live-Hack-CVE/CVE-2023-21753](https://github.com/Live-Hack-CVE/CVE-2023-21753)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21753">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21753">

---
## CVE-2023-21752 (2023-01-10T22:15:00)
> Windows Backup Service Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21752](https://github.com/Live-Hack-CVE/CVE-2023-21752)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21752">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21752">
- [Wh04m1001/CVE-2023-21752](https://github.com/Wh04m1001/CVE-2023-21752)	<img alt="forks" src="https://img.shields.io/github/forks/Wh04m1001/CVE-2023-21752">	<img alt="stars" src="https://img.shields.io/github/stars/Wh04m1001/CVE-2023-21752">

---
## CVE-2023-21750 (2023-01-10T22:15:00)
> Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21747, CVE-2023-21748, CVE-2023-21749, CVE-2023-21754, CVE-2023-21755, CVE-2023-21772, CVE-2023-21773, CVE-2023-21774.
- [Live-Hack-CVE/CVE-2023-21750](https://github.com/Live-Hack-CVE/CVE-2023-21750)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21750">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21750">
- [Live-Hack-CVE/CVE-2023-21747](https://github.com/Live-Hack-CVE/CVE-2023-21747)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21747">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21747">
- [Live-Hack-CVE/CVE-2023-21749](https://github.com/Live-Hack-CVE/CVE-2023-21749)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21749">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21749">
- [Live-Hack-CVE/CVE-2023-21748](https://github.com/Live-Hack-CVE/CVE-2023-21748)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21748">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21748">
- [Live-Hack-CVE/CVE-2023-21754](https://github.com/Live-Hack-CVE/CVE-2023-21754)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21754">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21754">
- [Live-Hack-CVE/CVE-2023-21773](https://github.com/Live-Hack-CVE/CVE-2023-21773)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21773">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21773">
- [Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772">
- [Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675">
- [Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755">
- [Live-Hack-CVE/CVE-2023-21774](https://github.com/Live-Hack-CVE/CVE-2023-21774)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21774">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21774">

---
## CVE-2023-21749 (2023-01-10T22:15:00)
> Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21747, CVE-2023-21748, CVE-2023-21750, CVE-2023-21754, CVE-2023-21755, CVE-2023-21772, CVE-2023-21773, CVE-2023-21774.
- [Live-Hack-CVE/CVE-2023-21749](https://github.com/Live-Hack-CVE/CVE-2023-21749)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21749">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21749">
- [Live-Hack-CVE/CVE-2023-21747](https://github.com/Live-Hack-CVE/CVE-2023-21747)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21747">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21747">
- [Live-Hack-CVE/CVE-2023-21750](https://github.com/Live-Hack-CVE/CVE-2023-21750)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21750">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21750">
- [Live-Hack-CVE/CVE-2023-21748](https://github.com/Live-Hack-CVE/CVE-2023-21748)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21748">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21748">
- [Live-Hack-CVE/CVE-2023-21754](https://github.com/Live-Hack-CVE/CVE-2023-21754)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21754">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21754">
- [Live-Hack-CVE/CVE-2023-21773](https://github.com/Live-Hack-CVE/CVE-2023-21773)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21773">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21773">
- [Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772">
- [Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675">
- [Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755">

---
## CVE-2023-21748 (2023-01-10T22:15:00)
> Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21747, CVE-2023-21749, CVE-2023-21750, CVE-2023-21754, CVE-2023-21755, CVE-2023-21772, CVE-2023-21773, CVE-2023-21774.
- [Live-Hack-CVE/CVE-2023-21748](https://github.com/Live-Hack-CVE/CVE-2023-21748)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21748">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21748">
- [Live-Hack-CVE/CVE-2023-21747](https://github.com/Live-Hack-CVE/CVE-2023-21747)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21747">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21747">
- [Live-Hack-CVE/CVE-2023-21749](https://github.com/Live-Hack-CVE/CVE-2023-21749)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21749">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21749">
- [Live-Hack-CVE/CVE-2023-21750](https://github.com/Live-Hack-CVE/CVE-2023-21750)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21750">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21750">
- [Live-Hack-CVE/CVE-2023-21754](https://github.com/Live-Hack-CVE/CVE-2023-21754)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21754">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21754">
- [Live-Hack-CVE/CVE-2023-21773](https://github.com/Live-Hack-CVE/CVE-2023-21773)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21773">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21773">
- [Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772">
- [Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675">
- [Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755">

---
## CVE-2023-21747 (2023-01-10T22:15:00)
> Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21675, CVE-2023-21748, CVE-2023-21749, CVE-2023-21750, CVE-2023-21754, CVE-2023-21755, CVE-2023-21772, CVE-2023-21773, CVE-2023-21774.
- [Live-Hack-CVE/CVE-2023-21747](https://github.com/Live-Hack-CVE/CVE-2023-21747)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21747">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21747">
- [Live-Hack-CVE/CVE-2023-21749](https://github.com/Live-Hack-CVE/CVE-2023-21749)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21749">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21749">
- [Live-Hack-CVE/CVE-2023-21750](https://github.com/Live-Hack-CVE/CVE-2023-21750)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21750">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21750">
- [Live-Hack-CVE/CVE-2023-21748](https://github.com/Live-Hack-CVE/CVE-2023-21748)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21748">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21748">
- [Live-Hack-CVE/CVE-2023-21754](https://github.com/Live-Hack-CVE/CVE-2023-21754)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21754">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21754">
- [Live-Hack-CVE/CVE-2023-21773](https://github.com/Live-Hack-CVE/CVE-2023-21773)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21773">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21773">
- [Live-Hack-CVE/CVE-2023-21772](https://github.com/Live-Hack-CVE/CVE-2023-21772)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21772">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21772">
- [Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675">
- [Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755">

---
## CVE-2023-21746 (2023-01-10T22:15:00)
> Windows NTLM Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21746](https://github.com/Live-Hack-CVE/CVE-2023-21746)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21746">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21746">

---
## CVE-2023-21745 (2023-01-10T22:15:00)
> Microsoft Exchange Server Spoofing Vulnerability. This CVE ID is unique from CVE-2023-21762.
- [Live-Hack-CVE/CVE-2023-21745](https://github.com/Live-Hack-CVE/CVE-2023-21745)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21745">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21745">

---
## CVE-2023-21744 (2023-01-10T22:15:00)
> Microsoft SharePoint Server Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21742.
- [Live-Hack-CVE/CVE-2023-21744](https://github.com/Live-Hack-CVE/CVE-2023-21744)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21744">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21744">
- [Live-Hack-CVE/CVE-2023-21742](https://github.com/Live-Hack-CVE/CVE-2023-21742)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21742">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21742">

---
## CVE-2023-21743 (2023-01-10T22:15:00)
> Microsoft SharePoint Server Security Feature Bypass Vulnerability.
- [Live-Hack-CVE/CVE-2023-21743](https://github.com/Live-Hack-CVE/CVE-2023-21743)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21743">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21743">

---
## CVE-2023-21742 (2023-01-10T22:15:00)
> Microsoft SharePoint Server Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21744.
- [Live-Hack-CVE/CVE-2023-21742](https://github.com/Live-Hack-CVE/CVE-2023-21742)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21742">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21742">
- [Live-Hack-CVE/CVE-2023-21744](https://github.com/Live-Hack-CVE/CVE-2023-21744)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21744">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21744">

---
## CVE-2023-21739 (2023-01-10T22:15:00)
> Windows Bluetooth Driver Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21739](https://github.com/Live-Hack-CVE/CVE-2023-21739)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21739">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21739">

---
## CVE-2023-21736 (2023-01-10T22:15:00)
> Microsoft Office Visio Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21737, CVE-2023-21738.
- [Live-Hack-CVE/CVE-2023-21736](https://github.com/Live-Hack-CVE/CVE-2023-21736)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21736">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21736">

---
## CVE-2023-21735 (2023-01-10T22:15:00)
> Microsoft Office Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21734.
- [Live-Hack-CVE/CVE-2023-21735](https://github.com/Live-Hack-CVE/CVE-2023-21735)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21735">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21735">
- [Live-Hack-CVE/CVE-2023-21734](https://github.com/Live-Hack-CVE/CVE-2023-21734)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21734">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21734">

---
## CVE-2023-21734 (2023-01-10T22:15:00)
> Microsoft Office Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21735.
- [Live-Hack-CVE/CVE-2023-21734](https://github.com/Live-Hack-CVE/CVE-2023-21734)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21734">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21734">
- [Live-Hack-CVE/CVE-2023-21735](https://github.com/Live-Hack-CVE/CVE-2023-21735)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21735">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21735">

---
## CVE-2023-21733 (2023-01-10T22:15:00)
> Windows Bind Filter Driver Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21733](https://github.com/Live-Hack-CVE/CVE-2023-21733)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21733">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21733">

---
## CVE-2023-21732 (2023-01-10T22:15:00)
> Microsoft ODBC Driver Remote Code Execution Vulnerability.
- [Live-Hack-CVE/CVE-2023-21732](https://github.com/Live-Hack-CVE/CVE-2023-21732)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21732">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21732">

---
## CVE-2023-21730 (2023-01-10T22:15:00)
> Microsoft Cryptographic Services Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21551, CVE-2023-21561.
- [Live-Hack-CVE/CVE-2023-21730](https://github.com/Live-Hack-CVE/CVE-2023-21730)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21730">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21730">
- [Live-Hack-CVE/CVE-2023-21551](https://github.com/Live-Hack-CVE/CVE-2023-21551)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21551">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21551">
- [Live-Hack-CVE/CVE-2023-21561](https://github.com/Live-Hack-CVE/CVE-2023-21561)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21561">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21561">

---
## CVE-2023-21728 (2023-01-10T22:15:00)
> Windows Netlogon Denial of Service Vulnerability.
- [Live-Hack-CVE/CVE-2023-21728](https://github.com/Live-Hack-CVE/CVE-2023-21728)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21728">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21728">

---
## CVE-2023-21726 (2023-01-10T22:15:00)
> Windows Credential Manager User Interface Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21726](https://github.com/Live-Hack-CVE/CVE-2023-21726)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21726">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21726">

---
## CVE-2023-21725 (2023-01-10T22:15:00)
> Windows Malicious Software Removal Tool Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21725](https://github.com/Live-Hack-CVE/CVE-2023-21725)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21725">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21725">

---
## CVE-2023-21724 (2023-01-10T22:15:00)
> Microsoft DWM Core Library Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21724](https://github.com/Live-Hack-CVE/CVE-2023-21724)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21724">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21724">

---
## CVE-2023-21683 (2023-01-10T22:15:00)
> Windows Internet Key Exchange (IKE) Extension Denial of Service Vulnerability. This CVE ID is unique from CVE-2023-21677, CVE-2023-21758.
- [Live-Hack-CVE/CVE-2023-21683](https://github.com/Live-Hack-CVE/CVE-2023-21683)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21683">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21683">
- [Live-Hack-CVE/CVE-2023-21677](https://github.com/Live-Hack-CVE/CVE-2023-21677)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21677">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21677">

---
## CVE-2023-21682 (2023-01-10T22:15:00)
> Windows Point-to-Point Protocol (PPP) Information Disclosure Vulnerability.
- [Live-Hack-CVE/CVE-2023-21682](https://github.com/Live-Hack-CVE/CVE-2023-21682)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21682">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21682">

---
## CVE-2023-21681 (2023-01-10T22:15:00)
> Microsoft WDAC OLE DB provider for SQL Server Remote Code Execution Vulnerability.
- [Live-Hack-CVE/CVE-2023-21681](https://github.com/Live-Hack-CVE/CVE-2023-21681)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21681">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21681">

---
## CVE-2023-21680 (2023-01-10T22:15:00)
> Windows Win32k Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21680](https://github.com/Live-Hack-CVE/CVE-2023-21680)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21680">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21680">

---
## CVE-2023-21679 (2023-01-10T22:15:00)
> Windows Layer 2 Tunneling Protocol (L2TP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21543, CVE-2023-21546, CVE-2023-21555, CVE-2023-21556.
- [Live-Hack-CVE/CVE-2023-21679](https://github.com/Live-Hack-CVE/CVE-2023-21679)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21679">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21679">
- [Live-Hack-CVE/CVE-2023-21555](https://github.com/Live-Hack-CVE/CVE-2023-21555)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21555">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21555">
- [Live-Hack-CVE/CVE-2023-21546](https://github.com/Live-Hack-CVE/CVE-2023-21546)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21546">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21546">
- [Live-Hack-CVE/CVE-2023-21543](https://github.com/Live-Hack-CVE/CVE-2023-21543)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21543">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21543">

---
## CVE-2023-21678 (2023-01-10T22:15:00)
> Windows Print Spooler Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21760, CVE-2023-21765.
- [Live-Hack-CVE/CVE-2023-21678](https://github.com/Live-Hack-CVE/CVE-2023-21678)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21678">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21678">
- [Live-Hack-CVE/CVE-2023-21765](https://github.com/Live-Hack-CVE/CVE-2023-21765)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21765">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21765">

---
## CVE-2023-21677 (2023-01-10T22:15:00)
> Windows Internet Key Exchange (IKE) Extension Denial of Service Vulnerability. This CVE ID is unique from CVE-2023-21683, CVE-2023-21758.
- [Live-Hack-CVE/CVE-2023-21677](https://github.com/Live-Hack-CVE/CVE-2023-21677)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21677">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21677">

---
## CVE-2023-21676 (2023-01-10T22:15:00)
> Windows Lightweight Directory Access Protocol (LDAP) Remote Code Execution Vulnerability.
- [Live-Hack-CVE/CVE-2023-21676](https://github.com/Live-Hack-CVE/CVE-2023-21676)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21676">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21676">

---
## CVE-2023-21675 (2023-01-10T22:15:00)
> Windows Kernel Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21747, CVE-2023-21748, CVE-2023-21749, CVE-2023-21750, CVE-2023-21754, CVE-2023-21755, CVE-2023-21772, CVE-2023-21773, CVE-2023-21774.
- [Live-Hack-CVE/CVE-2023-21675](https://github.com/Live-Hack-CVE/CVE-2023-21675)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21675">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21675">
- [Live-Hack-CVE/CVE-2023-21755](https://github.com/Live-Hack-CVE/CVE-2023-21755)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21755">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21755">

---
## CVE-2023-21674 (2023-01-10T22:15:00)
> Windows Advanced Local Procedure Call (ALPC) Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21674](https://github.com/Live-Hack-CVE/CVE-2023-21674)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21674">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21674">

---
## CVE-2023-21606 (2023-01-18T19:15:00)
> Adobe Acrobat Reader versions 22.003.20282 (and earlier), 22.003.20281 (and earlier) and 20.005.30418 (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
- [Live-Hack-CVE/CVE-2023-21606](https://github.com/Live-Hack-CVE/CVE-2023-21606)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21606">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21606">

---
## CVE-2023-21605 (2023-01-18T19:15:00)
> Adobe Acrobat Reader versions 22.003.20282 (and earlier), 22.003.20281 (and earlier) and 20.005.30418 (and earlier) are affected by a Heap-based Buffer Overflow vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
- [Live-Hack-CVE/CVE-2023-21605](https://github.com/Live-Hack-CVE/CVE-2023-21605)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21605">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21605">

---
## CVE-2023-21603 (2023-01-18T18:15:00)
> Adobe Dimension version 3.4.6 (and earlier) are affected by an out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
- [Live-Hack-CVE/CVE-2023-21603](https://github.com/Live-Hack-CVE/CVE-2023-21603)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21603">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21603">

---
## CVE-2023-21601 (2023-01-18T18:15:00)
> Adobe Dimension version 3.4.6 (and earlier) are affected by a Use After Free vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
- [Live-Hack-CVE/CVE-2023-21601](https://github.com/Live-Hack-CVE/CVE-2023-21601)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21601">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21601">

---
## CVE-2023-21599 (2023-01-13T21:15:00)
> Adobe InCopy versions 18.0 (and earlier), 17.4 (and earlier) are affected by an out-of-bounds read vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
- [Live-Hack-CVE/CVE-2023-21599](https://github.com/Live-Hack-CVE/CVE-2023-21599)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21599">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21599">

---
## CVE-2023-21598 (2023-01-13T21:15:00)
> Adobe InCopy versions 18.0 (and earlier), 17.4 (and earlier) are affected by a Use After Free vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
- [Live-Hack-CVE/CVE-2023-21598](https://github.com/Live-Hack-CVE/CVE-2023-21598)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21598">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21598">

---
## CVE-2023-21597 (2023-01-13T21:15:00)
> Adobe InCopy versions 18.0 (and earlier), 17.4 (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
- [Live-Hack-CVE/CVE-2023-21597](https://github.com/Live-Hack-CVE/CVE-2023-21597)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21597">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21597">

---
## CVE-2023-21596 (2023-01-13T21:15:00)
> Adobe InCopy versions 18.0 (and earlier), 17.4 (and earlier) are affected by an Improper Input Validation vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
- [Live-Hack-CVE/CVE-2023-21596](https://github.com/Live-Hack-CVE/CVE-2023-21596)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21596">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21596">

---
## CVE-2023-21595 (2023-01-13T21:15:00)
> Adobe InCopy versions 18.0 (and earlier), 17.4 (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
- [Live-Hack-CVE/CVE-2023-21595](https://github.com/Live-Hack-CVE/CVE-2023-21595)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21595">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21595">

---
## CVE-2023-21594 (2023-01-13T21:15:00)
> Adobe InCopy versions 18.0 (and earlier), 17.4 (and earlier) are affected by a Heap-based Buffer Overflow vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
- [Live-Hack-CVE/CVE-2023-21594](https://github.com/Live-Hack-CVE/CVE-2023-21594)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21594">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21594">

---
## CVE-2023-21589 (2023-01-13T20:15:00)
> Adobe InDesign version 18.0 (and earlier), 17.4 (and earlier) are affected by an out-of-bounds write vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
- [Live-Hack-CVE/CVE-2023-21589](https://github.com/Live-Hack-CVE/CVE-2023-21589)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21589">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21589">

---
## CVE-2023-21588 (2023-01-13T20:15:00)
> Adobe InDesign version 18.0 (and earlier), 17.4 (and earlier) are affected by an Improper Input Validation vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
- [Live-Hack-CVE/CVE-2023-21588](https://github.com/Live-Hack-CVE/CVE-2023-21588)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21588">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21588">

---
## CVE-2023-21587 (2023-01-13T20:15:00)
> Adobe InDesign version 18.0 (and earlier), 17.4 (and earlier) are affected by a Heap-based Buffer Overflow vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.
- [Live-Hack-CVE/CVE-2023-21587](https://github.com/Live-Hack-CVE/CVE-2023-21587)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21587">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21587">

---
## CVE-2023-21563 (2023-01-10T22:15:00)
> BitLocker Security Feature Bypass Vulnerability.
- [Live-Hack-CVE/CVE-2023-21563](https://github.com/Live-Hack-CVE/CVE-2023-21563)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21563">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21563">

---
## CVE-2023-21561 (2023-01-10T22:15:00)
> Microsoft Cryptographic Services Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21551, CVE-2023-21730.
- [Live-Hack-CVE/CVE-2023-21561](https://github.com/Live-Hack-CVE/CVE-2023-21561)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21561">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21561">

---
## CVE-2023-21560 (2023-01-10T22:15:00)
> Windows Boot Manager Security Feature Bypass Vulnerability.
- [Live-Hack-CVE/CVE-2023-21560](https://github.com/Live-Hack-CVE/CVE-2023-21560)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21560">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21560">

---
## CVE-2023-21559 (2023-01-10T22:15:00)
> Windows Cryptographic Information Disclosure Vulnerability. This CVE ID is unique from CVE-2023-21540, CVE-2023-21550.
- [Live-Hack-CVE/CVE-2023-21559](https://github.com/Live-Hack-CVE/CVE-2023-21559)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21559">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21559">
- [Live-Hack-CVE/CVE-2023-21550](https://github.com/Live-Hack-CVE/CVE-2023-21550)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21550">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21550">
- [Live-Hack-CVE/CVE-2023-21540](https://github.com/Live-Hack-CVE/CVE-2023-21540)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21540">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21540">

---
## CVE-2023-21558 (2023-01-10T22:15:00)
> Windows Error Reporting Service Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21558](https://github.com/Live-Hack-CVE/CVE-2023-21558)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21558">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21558">

---
## CVE-2023-21555 (2023-01-10T22:15:00)
> Windows Layer 2 Tunneling Protocol (L2TP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21543, CVE-2023-21546, CVE-2023-21556, CVE-2023-21679.
- [Live-Hack-CVE/CVE-2023-21555](https://github.com/Live-Hack-CVE/CVE-2023-21555)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21555">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21555">
- [Live-Hack-CVE/CVE-2023-21546](https://github.com/Live-Hack-CVE/CVE-2023-21546)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21546">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21546">
- [Live-Hack-CVE/CVE-2023-21543](https://github.com/Live-Hack-CVE/CVE-2023-21543)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21543">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21543">

---
## CVE-2023-21551 (2023-01-10T22:15:00)
> Microsoft Cryptographic Services Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21561, CVE-2023-21730.
- [Live-Hack-CVE/CVE-2023-21551](https://github.com/Live-Hack-CVE/CVE-2023-21551)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21551">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21551">
- [Live-Hack-CVE/CVE-2023-21561](https://github.com/Live-Hack-CVE/CVE-2023-21561)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21561">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21561">

---
## CVE-2023-21550 (2023-01-10T22:15:00)
> Windows Cryptographic Information Disclosure Vulnerability. This CVE ID is unique from CVE-2023-21540, CVE-2023-21559.
- [Live-Hack-CVE/CVE-2023-21550](https://github.com/Live-Hack-CVE/CVE-2023-21550)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21550">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21550">
- [Live-Hack-CVE/CVE-2023-21559](https://github.com/Live-Hack-CVE/CVE-2023-21559)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21559">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21559">
- [Live-Hack-CVE/CVE-2023-21540](https://github.com/Live-Hack-CVE/CVE-2023-21540)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21540">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21540">

---
## CVE-2023-21549 (2023-01-10T22:15:00)
> Windows SMB Witness Service Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21549](https://github.com/Live-Hack-CVE/CVE-2023-21549)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21549">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21549">

---
## CVE-2023-21548 (2023-01-10T22:15:00)
> Windows Secure Socket Tunneling Protocol (SSTP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21535.
- [Live-Hack-CVE/CVE-2023-21548](https://github.com/Live-Hack-CVE/CVE-2023-21548)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21548">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21548">
- [Live-Hack-CVE/CVE-2023-21535](https://github.com/Live-Hack-CVE/CVE-2023-21535)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21535">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21535">

---
## CVE-2023-21547 (2023-01-10T22:15:00)
> Internet Key Exchange (IKE) Protocol Denial of Service Vulnerability.
- [Live-Hack-CVE/CVE-2023-21547](https://github.com/Live-Hack-CVE/CVE-2023-21547)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21547">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21547">

---
## CVE-2023-21546 (2023-01-10T22:15:00)
> Windows Layer 2 Tunneling Protocol (L2TP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21543, CVE-2023-21555, CVE-2023-21556, CVE-2023-21679.
- [Live-Hack-CVE/CVE-2023-21546](https://github.com/Live-Hack-CVE/CVE-2023-21546)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21546">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21546">
- [Live-Hack-CVE/CVE-2023-21543](https://github.com/Live-Hack-CVE/CVE-2023-21543)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21543">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21543">

---
## CVE-2023-21543 (2023-01-10T22:15:00)
> Windows Layer 2 Tunneling Protocol (L2TP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21546, CVE-2023-21555, CVE-2023-21556, CVE-2023-21679.
- [Live-Hack-CVE/CVE-2023-21543](https://github.com/Live-Hack-CVE/CVE-2023-21543)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21543">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21543">
- [Live-Hack-CVE/CVE-2023-21546](https://github.com/Live-Hack-CVE/CVE-2023-21546)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21546">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21546">

---
## CVE-2023-21542 (2023-01-10T22:15:00)
> Windows Installer Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21542](https://github.com/Live-Hack-CVE/CVE-2023-21542)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21542">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21542">

---
## CVE-2023-21541 (2023-01-10T22:15:00)
> Windows Task Scheduler Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21541](https://github.com/Live-Hack-CVE/CVE-2023-21541)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21541">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21541">

---
## CVE-2023-21540 (2023-01-10T22:15:00)
> Windows Cryptographic Information Disclosure Vulnerability. This CVE ID is unique from CVE-2023-21550, CVE-2023-21559.
- [Live-Hack-CVE/CVE-2023-21540](https://github.com/Live-Hack-CVE/CVE-2023-21540)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21540">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21540">

---
## CVE-2023-21539 (2023-01-10T22:15:00)
> Windows Authentication Remote Code Execution Vulnerability.
- [Live-Hack-CVE/CVE-2023-21539](https://github.com/Live-Hack-CVE/CVE-2023-21539)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21539">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21539">

---
## CVE-2023-21538 (2023-01-10T22:15:00)
> .NET Denial of Service Vulnerability.
- [Live-Hack-CVE/CVE-2023-21538](https://github.com/Live-Hack-CVE/CVE-2023-21538)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21538">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21538">

---
## CVE-2023-21537 (2023-01-10T22:15:00)
> Microsoft Message Queuing (MSMQ) Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21537](https://github.com/Live-Hack-CVE/CVE-2023-21537)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21537">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21537">

---
## CVE-2023-21536 (2023-01-10T22:15:00)
> Event Tracing for Windows Information Disclosure Vulnerability. This CVE ID is unique from CVE-2023-21753.
- [Live-Hack-CVE/CVE-2023-21536](https://github.com/Live-Hack-CVE/CVE-2023-21536)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21536">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21536">

---
## CVE-2023-21535 (2023-01-10T22:15:00)
> Windows Secure Socket Tunneling Protocol (SSTP) Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2023-21548.
- [Live-Hack-CVE/CVE-2023-21535](https://github.com/Live-Hack-CVE/CVE-2023-21535)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21535">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21535">
- [Live-Hack-CVE/CVE-2023-21548](https://github.com/Live-Hack-CVE/CVE-2023-21548)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21548">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21548">

---
## CVE-2023-21532 (2023-01-10T22:15:00)
> Windows GDI Elevation of Privilege Vulnerability. This CVE ID is unique from CVE-2023-21552.
- [Live-Hack-CVE/CVE-2023-21532](https://github.com/Live-Hack-CVE/CVE-2023-21532)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21532">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21532">

---
## CVE-2023-21531 (2023-01-10T22:15:00)
> Azure Service Fabric Container Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21531](https://github.com/Live-Hack-CVE/CVE-2023-21531)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21531">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21531">

---
## CVE-2023-21527 (2023-01-10T22:15:00)
> Windows iSCSI Service Denial of Service Vulnerability.
- [Live-Hack-CVE/CVE-2023-21527](https://github.com/Live-Hack-CVE/CVE-2023-21527)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21527">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21527">

---
## CVE-2023-21525 (2023-01-10T22:15:00)
> Remote Procedure Call Runtime Denial of Service Vulnerability.
- [Live-Hack-CVE/CVE-2023-21525](https://github.com/Live-Hack-CVE/CVE-2023-21525)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21525">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21525">

---
## CVE-2023-21524 (2023-01-10T22:15:00)
> Windows Local Security Authority (LSA) Elevation of Privilege Vulnerability.
- [Live-Hack-CVE/CVE-2023-21524](https://github.com/Live-Hack-CVE/CVE-2023-21524)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-21524">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-21524">

---
## CVE-2023-20532 (2023-01-11T08:15:00)
> Insufficient input validation in the SMU may allow an attacker to improperly lock resources, potentially resulting in a denial of service.
- [Live-Hack-CVE/CVE-2023-20532](https://github.com/Live-Hack-CVE/CVE-2023-20532)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20532">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20532">

---
## CVE-2023-20531 (2023-01-11T08:15:00)
> Insufficient bound checks in the SMU may allow an attacker to update the SRAM from/to address space to an invalid value potentially resulting in a denial of service.
- [Live-Hack-CVE/CVE-2023-20531](https://github.com/Live-Hack-CVE/CVE-2023-20531)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20531">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20531">

---
## CVE-2023-20530 (2023-01-11T08:15:00)
> Insufficient input validation of BIOS mailbox messages in SMU may result in out-of-bounds memory reads potentially resulting in a denial of service.
- [Live-Hack-CVE/CVE-2023-20530](https://github.com/Live-Hack-CVE/CVE-2023-20530)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20530">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20530">

---
## CVE-2023-20529 (2023-01-11T08:15:00)
> Insufficient bound checks in the SMU may allow an attacker to update the from/to address space to an invalid value potentially resulting in a denial of service.
- [Live-Hack-CVE/CVE-2023-20529](https://github.com/Live-Hack-CVE/CVE-2023-20529)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20529">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20529">

---
## CVE-2023-20528 (2023-01-11T08:15:00)
> Insufficient input validation in the SMU may allow a physical attacker to exfiltrate SMU memory contents over the I2C bus potentially leading to a loss of confidentiality.
- [Live-Hack-CVE/CVE-2023-20528](https://github.com/Live-Hack-CVE/CVE-2023-20528)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20528">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20528">

---
## CVE-2023-20527 (2023-01-11T08:15:00)
> Improper syscall input validation in the ASP Bootloader may allow a privileged attacker to read memory out-of-bounds, potentially leading to a denial-of-service.
- [Live-Hack-CVE/CVE-2023-20527](https://github.com/Live-Hack-CVE/CVE-2023-20527)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20527">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20527">

---
## CVE-2023-20525 (2023-01-11T08:15:00)
> Insufficient syscall input validation in the ASP Bootloader may allow a privileged attacker to read memory outside the bounds of a mapped register potentially leading to a denial of service.
- [Live-Hack-CVE/CVE-2023-20525](https://github.com/Live-Hack-CVE/CVE-2023-20525)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20525">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20525">

---
## CVE-2023-20523 (2023-01-11T08:15:00)
> TOCTOU in the ASP may allow a physical attacker to write beyond the buffer bounds, potentially leading to a loss of integrity or denial of service.
- [Live-Hack-CVE/CVE-2023-20523](https://github.com/Live-Hack-CVE/CVE-2023-20523)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20523">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20523">

---
## CVE-2023-20522 (2023-01-11T08:15:00)
> Insufficient input validation in ASP may allow an attacker with a malicious BIOS to potentially cause a denial of service.
- [Live-Hack-CVE/CVE-2023-20522](https://github.com/Live-Hack-CVE/CVE-2023-20522)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-20522">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-20522">

---
## CVE-2023-0440 (2023-01-23T14:15:00)
> Exposure of Sensitive Information to an Unauthorized Actor in GitHub repository healthchecks/healthchecks prior to v2.6.
- [Live-Hack-CVE/CVE-2023-0440](https://github.com/Live-Hack-CVE/CVE-2023-0440)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0440">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0440">

---
## CVE-2023-0438 (2023-01-23T14:15:00)
> Cross-Site Request Forgery (CSRF) in GitHub repository modoboa/modoboa prior to 2.0.4.
- [Live-Hack-CVE/CVE-2023-0438](https://github.com/Live-Hack-CVE/CVE-2023-0438)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0438">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0438">

---
## CVE-2023-0435 (2023-01-22T22:15:00)
> Excessive Attack Surface in GitHub repository pyload/pyload prior to 0.5.0b3.dev41.
- [Live-Hack-CVE/CVE-2023-0435](https://github.com/Live-Hack-CVE/CVE-2023-0435)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0435">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0435">

---
## CVE-2023-0434 (2023-01-22T01:15:00)
> Improper Input Validation in GitHub repository pyload/pyload prior to 0.5.0b3.dev40.
- [Live-Hack-CVE/CVE-2023-0434](https://github.com/Live-Hack-CVE/CVE-2023-0434)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0434">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0434">

---
## CVE-2023-0433 (2023-01-21T15:15:00)
> Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1225.
- [Live-Hack-CVE/CVE-2023-0433](https://github.com/Live-Hack-CVE/CVE-2023-0433)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0433">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0433">

---
## CVE-2023-0406 (2023-01-19T18:15:00)
> Cross-Site Request Forgery (CSRF) in GitHub repository modoboa/modoboa prior to 2.0.4.
- [Live-Hack-CVE/CVE-2023-0406](https://github.com/Live-Hack-CVE/CVE-2023-0406)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0406">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0406">

---
## CVE-2023-0404 (2023-01-19T15:15:00)
> The Events Made Easy plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on several functions related to AJAX actions in versions up to, and including, 2.3.16. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to invoke those functions intended for administrator use. While the plugin is still pending review from the WordPress repository, site owners can download a copy of the patched version directly from the developer's Github at https://github.com/liedekef/events-made-easy
- [Live-Hack-CVE/CVE-2023-0404](https://github.com/Live-Hack-CVE/CVE-2023-0404)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0404">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0404">

---
## CVE-2023-0403 (2023-01-19T15:15:00)
> The Social Warfare plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 4.4.0. This is due to missing or incorrect nonce validation on several AJAX actions. This makes it possible for unauthenticated attackers to delete post meta information and reset network access tokens, via forged request granted they can trick a site administrator into performing an action such as clicking on a link.
- [Live-Hack-CVE/CVE-2023-0403](https://github.com/Live-Hack-CVE/CVE-2023-0403)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0403">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0403">

---
## CVE-2023-0402 (2023-01-19T15:15:00)
> The Social Warfare plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on several AJAX actions in versions up to, and including, 4.3.0. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to delete post meta information and reset network access tokens.
- [Live-Hack-CVE/CVE-2023-0402](https://github.com/Live-Hack-CVE/CVE-2023-0402)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0402">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0402">

---
## CVE-2023-0398 (2023-01-19T09:15:00)
> Cross-Site Request Forgery (CSRF) in GitHub repository modoboa/modoboa prior to 2.0.4.
- [Live-Hack-CVE/CVE-2023-0398](https://github.com/Live-Hack-CVE/CVE-2023-0398)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0398">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0398">

---
## CVE-2023-0397 (2023-01-19T06:15:00)
> A malicious / defect bluetooth controller can cause a Denial of Service due to unchecked input in le_read_buffer_size_complete.
- [Live-Hack-CVE/CVE-2023-0397](https://github.com/Live-Hack-CVE/CVE-2023-0397)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0397">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0397">

---
## CVE-2023-0385 (2023-01-18T15:15:00)
> The Custom 404 Pro plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 3.7.1. This is due to missing or incorrect nonce validation on the custom_404_pro_admin_init function. This makes it possible for unauthenticated attackers to delete logs, via forged request granted they can trick a site administrator into performing an action such as clicking on a link.
- [Live-Hack-CVE/CVE-2023-0385](https://github.com/Live-Hack-CVE/CVE-2023-0385)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0385">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0385">

---
## CVE-2023-0358 (2023-01-18T02:15:00)
> Use After Free in GitHub repository gpac/gpac prior to 2.3.0-DEV.
- [Live-Hack-CVE/CVE-2023-0358](https://github.com/Live-Hack-CVE/CVE-2023-0358)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0358">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0358">

---
## CVE-2023-0338 (2023-01-17T16:15:00)
> Cross-site Scripting (XSS) - Reflected in GitHub repository lirantal/daloradius prior to master-branch.
- [Live-Hack-CVE/CVE-2023-0338](https://github.com/Live-Hack-CVE/CVE-2023-0338)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0338">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0338">

---
## CVE-2023-0337 (2023-01-17T16:15:00)
> Cross-site Scripting (XSS) - Reflected in GitHub repository lirantal/daloradius prior to master-branch.
- [Live-Hack-CVE/CVE-2023-0337](https://github.com/Live-Hack-CVE/CVE-2023-0337)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0337">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0337">

---
## CVE-2023-0332 (2023-01-17T08:15:00)
> A vulnerability was found in SourceCodester Online Food Ordering System 2.0. It has been classified as critical. Affected is an unknown function of the file admin/manage_user.php. The manipulation of the argument id leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-218472.
- [Live-Hack-CVE/CVE-2023-0332](https://github.com/Live-Hack-CVE/CVE-2023-0332)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0332">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0332">

---
## CVE-2023-0327 (2023-01-16T19:15:00)
> A vulnerability was found in saemorris TheRadSystem. It has been classified as problematic. Affected is an unknown function of the file users.php. The manipulation of the argument q leads to cross site scripting. It is possible to launch the attack remotely. VDB-218454 is the identifier assigned to this vulnerability.
- [Live-Hack-CVE/CVE-2023-0327](https://github.com/Live-Hack-CVE/CVE-2023-0327)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0327">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0327">

---
## CVE-2023-0316 (2023-01-16T01:15:00)
> Path Traversal: '\..\filename' in GitHub repository froxlor/froxlor prior to 2.0.0.
- [Live-Hack-CVE/CVE-2023-0316](https://github.com/Live-Hack-CVE/CVE-2023-0316)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0316">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0316">

---
## CVE-2023-0315 (2023-01-16T01:15:00)
> Command Injection in GitHub repository froxlor/froxlor prior to 2.0.8.
- [Live-Hack-CVE/CVE-2023-0315](https://github.com/Live-Hack-CVE/CVE-2023-0315)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0315">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0315">

---
## CVE-2023-0314 (2023-01-15T22:15:00)
> Cross-site Scripting (XSS) - Reflected in GitHub repository thorsten/phpmyfaq prior to 3.1.10.
- [Live-Hack-CVE/CVE-2023-0314](https://github.com/Live-Hack-CVE/CVE-2023-0314)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0314">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0314">

---
## CVE-2023-0313 (2023-01-15T22:15:00)
> Cross-site Scripting (XSS) - Stored in GitHub repository thorsten/phpmyfaq prior to 3.1.10.
- [Live-Hack-CVE/CVE-2023-0313](https://github.com/Live-Hack-CVE/CVE-2023-0313)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0313">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0313">

---
## CVE-2023-0312 (2023-01-15T22:15:00)
> Cross-site Scripting (XSS) - Stored in GitHub repository thorsten/phpmyfaq prior to 3.1.10.
- [Live-Hack-CVE/CVE-2023-0312](https://github.com/Live-Hack-CVE/CVE-2023-0312)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0312">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0312">

---
## CVE-2023-0311 (2023-01-15T22:15:00)
> Improper Authentication in GitHub repository thorsten/phpmyfaq prior to 3.1.10.
- [Live-Hack-CVE/CVE-2023-0311](https://github.com/Live-Hack-CVE/CVE-2023-0311)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0311">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0311">

---
## CVE-2023-0310 (2023-01-15T22:15:00)
> Cross-site Scripting (XSS) - Stored in GitHub repository thorsten/phpmyfaq prior to 3.1.10.
- [Live-Hack-CVE/CVE-2023-0310](https://github.com/Live-Hack-CVE/CVE-2023-0310)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0310">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0310">

---
## CVE-2023-0309 (2023-01-15T22:15:00)
> Cross-site Scripting (XSS) - Stored in GitHub repository thorsten/phpmyfaq prior to 3.1.10.
- [Live-Hack-CVE/CVE-2023-0309](https://github.com/Live-Hack-CVE/CVE-2023-0309)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0309">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0309">

---
## CVE-2023-0308 (2023-01-15T22:15:00)
> Cross-site Scripting (XSS) - Stored in GitHub repository thorsten/phpmyfaq prior to 3.1.10.
- [Live-Hack-CVE/CVE-2023-0308](https://github.com/Live-Hack-CVE/CVE-2023-0308)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0308">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0308">

---
## CVE-2023-0307 (2023-01-15T22:15:00)
> Weak Password Requirements in GitHub repository thorsten/phpmyfaq prior to 3.1.10.
- [Live-Hack-CVE/CVE-2023-0307](https://github.com/Live-Hack-CVE/CVE-2023-0307)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0307">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0307">

---
## CVE-2023-0306 (2023-01-15T22:15:00)
> Cross-site Scripting (XSS) - Stored in GitHub repository thorsten/phpmyfaq prior to 3.1.10.
- [Live-Hack-CVE/CVE-2023-0306](https://github.com/Live-Hack-CVE/CVE-2023-0306)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0306">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0306">

---
## CVE-2023-0305 (2023-01-15T12:15:00)
> A vulnerability classified as critical was found in SourceCodester Online Food Ordering System. This vulnerability affects unknown code of the file admin_class.php of the component Login Module. The manipulation of the argument username leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-218386 is the identifier assigned to this vulnerability.
- [Live-Hack-CVE/CVE-2023-0305](https://github.com/Live-Hack-CVE/CVE-2023-0305)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0305">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0305">

---
## CVE-2023-0304 (2023-01-15T12:15:00)
> A vulnerability classified as critical has been found in SourceCodester Online Food Ordering System. This affects an unknown part of the file admin_class.php of the component Signup Module. The manipulation of the argument email leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-218385 was assigned to this vulnerability.
- [Live-Hack-CVE/CVE-2023-0304](https://github.com/Live-Hack-CVE/CVE-2023-0304)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0304">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0304">

---
## CVE-2023-0303 (2023-01-15T12:15:00)
> A vulnerability was found in SourceCodester Online Food Ordering System. It has been rated as critical. Affected by this issue is some unknown functionality of the file view_prod.php. The manipulation of the argument id leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-218384.
- [Live-Hack-CVE/CVE-2023-0303](https://github.com/Live-Hack-CVE/CVE-2023-0303)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0303">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0303">

---
## CVE-2023-0302 (2023-01-15T01:15:00)
> Failure to Sanitize Special Elements into a Different Plane (Special Element Injection) in GitHub repository radareorg/radare2 prior to 5.8.2.
- [Live-Hack-CVE/CVE-2023-0302](https://github.com/Live-Hack-CVE/CVE-2023-0302)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0302">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0302">

---
## CVE-2023-0301 (2023-01-14T18:15:00)
> Cross-site Scripting (XSS) - Stored in GitHub repository alfio-event/alf.io prior to Alf.io 2.0-M4-2301.
- [Live-Hack-CVE/CVE-2023-0301](https://github.com/Live-Hack-CVE/CVE-2023-0301)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0301">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0301">

---
## CVE-2023-0300 (2023-01-14T18:15:00)
> Cross-site Scripting (XSS) - Reflected in GitHub repository alfio-event/alf.io prior to 2.0-M4-2301.
- [Live-Hack-CVE/CVE-2023-0300](https://github.com/Live-Hack-CVE/CVE-2023-0300)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0300">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0300">

---
## CVE-2023-0299 (2023-01-14T15:15:00)
> Improper Input Validation in GitHub repository publify/publify prior to 9.2.10.
- [Live-Hack-CVE/CVE-2023-0299](https://github.com/Live-Hack-CVE/CVE-2023-0299)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0299">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0299">

---
## CVE-2023-0298 (2023-01-14T08:15:00)
> Improper Authorization in GitHub repository firefly-iii/firefly-iii prior to 5.8.0.
- [Live-Hack-CVE/CVE-2023-0298](https://github.com/Live-Hack-CVE/CVE-2023-0298)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0298">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0298">

---
## CVE-2023-0297 (2023-01-14T03:15:00)
> Code Injection in GitHub repository pyload/pyload prior to 0.5.0b3.dev31.
- [bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad](https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad)	<img alt="forks" src="https://img.shields.io/github/forks/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad">	<img alt="stars" src="https://img.shields.io/github/stars/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad">
- [Live-Hack-CVE/CVE-2023-0297](https://github.com/Live-Hack-CVE/CVE-2023-0297)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0297">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0297">

---
## CVE-2023-0295 (2023-01-13T20:15:00)
> The Launchpad plugin for WordPress is vulnerable to Stored Cross-Site Scripting via several of its settings parameters in versions up to, and including, 1.0.13 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.
- [Live-Hack-CVE/CVE-2023-0295](https://github.com/Live-Hack-CVE/CVE-2023-0295)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0295">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0295">

---
## CVE-2023-0294 (2023-01-13T20:15:00)
> The Mediamatic – Media Library Folders plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 2.8.1. This is due to missing or incorrect nonce validation on its AJAX actions function. This makes it possible for unauthenticated attackers to change image categories used by the plugin, via forged request granted they can trick a site administrator into performing an action such as clicking on a link.
- [Live-Hack-CVE/CVE-2023-0294](https://github.com/Live-Hack-CVE/CVE-2023-0294)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0294">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0294">

---
## CVE-2023-0293 (2023-01-13T20:15:00)
> The Mediamatic – Media Library Folders plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on its AJAX actions in versions up to, and including, 2.8.1. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to change image categories, which it uses to arrange them in folder views.
- [Live-Hack-CVE/CVE-2023-0293](https://github.com/Live-Hack-CVE/CVE-2023-0293)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0293">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0293">

---
## CVE-2023-0290 (2023-01-18T22:15:00)
> Rapid7 Velociraptor did not properly sanitize the client ID parameter to the CreateCollection API, allowing a directory traversal in where the collection task could be written. It was possible to provide a client id of "../clients/server" to schedule the collection for the server (as a server artifact), but only require privileges to schedule collections on the client. Normally, to schedule an artifact on the server, the COLLECT_SERVER permission is required. This permission is normally only granted to "administrator" role. Due to this issue, it is sufficient to have the COLLECT_CLIENT privilege, which is normally granted to the "investigator" role. To exploit this vulnerability, the attacker must already have a Velociraptor user account at least "investigator" level, and be able to authenticate to the GUI and issue an API call to the backend. Typically, most users deploy Velociraptor with limited access to a trusted group, and most users will already be administrators within the GUI. This issue affects Velociraptor versions before 0.6.7-5. Version 0.6.7-5, released January 16, 2023, fixes the issue.
- [Live-Hack-CVE/CVE-2023-0290](https://github.com/Live-Hack-CVE/CVE-2023-0290)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0290">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0290">

---
## CVE-2023-0289 (2023-01-13T16:15:00)
> Cross-site Scripting (XSS) - Stored in GitHub repository craigk5n/webcalendar prior to master.
- [Live-Hack-CVE/CVE-2023-0289](https://github.com/Live-Hack-CVE/CVE-2023-0289)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0289">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0289">

---
## CVE-2023-0288 (2023-01-13T16:15:00)
> Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1189.
- [Live-Hack-CVE/CVE-2023-0288](https://github.com/Live-Hack-CVE/CVE-2023-0288)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0288">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0288">

---
## CVE-2023-0283 (2023-01-13T10:15:00)
> A vulnerability classified as critical has been found in SourceCodester Online Flight Booking Management System. This affects an unknown part of the file review_search.php of the component POST Parameter Handler. The manipulation of the argument txtsearch leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-218277 was assigned to this vulnerability.
- [Live-Hack-CVE/CVE-2023-0283](https://github.com/Live-Hack-CVE/CVE-2023-0283)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0283">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0283">

---
## CVE-2023-0281 (2023-01-13T10:15:00)
> A vulnerability was found in SourceCodester Online Flight Booking Management System. It has been rated as critical. Affected by this issue is some unknown functionality of the file judge_panel.php. The manipulation of the argument subevent_id leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-218276.
- [Live-Hack-CVE/CVE-2023-0281](https://github.com/Live-Hack-CVE/CVE-2023-0281)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0281">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0281">

---
## CVE-2023-0258 (2023-01-12T22:15:00)
> A vulnerability was found in SourceCodester Online Food Ordering System 2.0. It has been rated as problematic. Affected by this issue is some unknown functionality of the component Category List Handler. The manipulation of the argument Reason with the input "><script>prompt(1)</script> leads to cross site scripting. The attack may be launched remotely. VDB-218186 is the identifier assigned to this vulnerability.
- [Live-Hack-CVE/CVE-2023-0258](https://github.com/Live-Hack-CVE/CVE-2023-0258)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0258">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0258">

---
## CVE-2023-0257 (2023-01-12T22:15:00)
> A vulnerability was found in SourceCodester Online Food Ordering System 2.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file /fos/admin/index.php?page=menu of the component Menu Form. The manipulation of the argument Image with the input <?php system($_GET['c']); ?> leads to unrestricted upload. The attack can be launched remotely. The identifier VDB-218185 was assigned to this vulnerability.
- [Live-Hack-CVE/CVE-2023-0257](https://github.com/Live-Hack-CVE/CVE-2023-0257)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0257">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0257">

---
## CVE-2023-0256 (2023-01-12T22:15:00)
> A vulnerability was found in SourceCodester Online Food Ordering System 2.0. It has been classified as critical. Affected is an unknown function of the file /fos/admin/ajax.php?action=login of the component Login Page. The manipulation of the argument Username leads to sql injection. It is possible to launch the attack remotely. The identifier of this vulnerability is VDB-218184.
- [Live-Hack-CVE/CVE-2023-0256](https://github.com/Live-Hack-CVE/CVE-2023-0256)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0256">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0256">

---
## CVE-2023-0254 (2023-01-12T18:15:00)
> The Simple Membership WP user Import plugin for WordPress is vulnerable to SQL Injection via the ‘orderby’ parameter in versions up to, and including, 1.7 due to insufficient escaping on the user supplied parameter. This makes it possible for authenticated attackers with administrative privileges to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.
- [Live-Hack-CVE/CVE-2023-0254](https://github.com/Live-Hack-CVE/CVE-2023-0254)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0254">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0254">

---
## CVE-2023-0247 (2023-01-12T17:15:00)
> Uncontrolled Search Path Element in GitHub repository bits-and-blooms/bloom prior to 3.3.1.
- [Live-Hack-CVE/CVE-2023-0247](https://github.com/Live-Hack-CVE/CVE-2023-0247)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0247">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0247">

---
## CVE-2023-0246 (2023-01-12T15:15:00)
> A vulnerability, which was classified as problematic, was found in earclink ESPCMS P8.21120101. Affected is an unknown function of the component Content Handler. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-218154 is the identifier assigned to this vulnerability.
- [Live-Hack-CVE/CVE-2023-0246](https://github.com/Live-Hack-CVE/CVE-2023-0246)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0246">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0246">

---
## CVE-2023-0245 (2023-01-12T15:15:00)
> A vulnerability, which was classified as critical, has been found in SourceCodester Online Flight Booking Management System. This issue affects some unknown processing of the file add_contestant.php. The manipulation of the argument add_contestant leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-218153 was assigned to this vulnerability.
- [Live-Hack-CVE/CVE-2023-0245](https://github.com/Live-Hack-CVE/CVE-2023-0245)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0245">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0245">

---
## CVE-2023-0244 (2023-01-12T15:15:00)
> A vulnerability classified as critical was found in TuziCMS 2.0.6. This vulnerability affects the function delall of the file \App\Manage\Controller\KefuController.class.php. The manipulation of the argument id leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-218152.
- [Live-Hack-CVE/CVE-2023-0244](https://github.com/Live-Hack-CVE/CVE-2023-0244)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0244">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0244">

---
## CVE-2023-0242 (2023-01-18T21:15:00)
> Rapid7 Velociraptor allows users to be created with different privileges on the server. Administrators are generally allowed to run any command on the server including writing arbitrary files. However, lower privilege users are generally forbidden from writing or modifying files on the server. The VQL copy() function applies permission checks for reading files but does not check for permission to write files. This allows a low privilege user (usually, users with the Velociraptor "investigator" role) to overwrite files on the server, including Velociraptor configuration files. To exploit this vulnerability, the attacker must already have a Velociraptor user account at a low privilege level (at least "analyst") and be able to log into the GUI and create a notebook where they can run the VQL query invoking the copy() VQL function. Typically, most users deploy Velociraptor with limited access to a trusted group (most users will be administrators within the GUI). This vulnerability is associated with program files https://github.Com/Velocidex/velociraptor/blob/master/vql/filesystem/copy.go https://github.Com/Velocidex/velociraptor/blob/master/vql/filesystem/copy.go and program routines copy(). This issue affects Velociraptor versions before 0.6.7-5. Version 0.6.7-5, released January 16, 2023, fixes the issue.
- [Live-Hack-CVE/CVE-2023-0242](https://github.com/Live-Hack-CVE/CVE-2023-0242)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0242">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0242">

---
## CVE-2023-0237 (2023-01-13T05:15:00)
> ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.
- [Live-Hack-CVE/CVE-2023-0237](https://github.com/Live-Hack-CVE/CVE-2023-0237)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0237">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0237">

---
## CVE-2023-0235 (2023-01-13T05:15:00)
> ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.
- [Live-Hack-CVE/CVE-2023-0235](https://github.com/Live-Hack-CVE/CVE-2023-0235)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0235">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0235">

---
## CVE-2023-0227 (2023-01-12T01:15:00)
> Insufficient Session Expiration in GitHub repository pyload/pyload prior to 0.5.0b3.dev36.
- [Live-Hack-CVE/CVE-2023-0227](https://github.com/Live-Hack-CVE/CVE-2023-0227)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0227">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0227">

---
## CVE-2023-0221 (2023-01-13T16:15:00)
> Product security bypass vulnerability in ACC prior to version 8.3.4 allows a locally logged-in attacker with administrator privileges to bypass the execution controls provided by ACC using the utilman program.
- [Live-Hack-CVE/CVE-2023-0221](https://github.com/Live-Hack-CVE/CVE-2023-0221)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0221">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0221">

---
## CVE-2023-0214 (2023-01-18T11:15:00)
> A cross-site scripting vulnerability in Skyhigh SWG in main releases 11.x prior to 11.2.6, 10.x prior to 10.2.17, and controlled release 12.x prior to 12.0.1 allows a remote attacker to craft SWG-specific internal requests with URL paths to any third-party website, causing arbitrary content to be injected into the response when accessed through SWG.
- [Live-Hack-CVE/CVE-2023-0214](https://github.com/Live-Hack-CVE/CVE-2023-0214)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0214">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0214">

---
## CVE-2023-0179 ()
> 
- [TurtleARM/CVE-2023-0179-PoC](https://github.com/TurtleARM/CVE-2023-0179-PoC)	<img alt="forks" src="https://img.shields.io/github/forks/TurtleARM/CVE-2023-0179-PoC">	<img alt="stars" src="https://img.shields.io/github/stars/TurtleARM/CVE-2023-0179-PoC">

---
## CVE-2023-0164 (2023-01-18T22:15:00)
> OrangeScrum version 2.0.11 allows an authenticated external attacker to execute arbitrary commands on the server. This is possible because the application injects an attacker-controlled parameter into a system function.
- [Live-Hack-CVE/CVE-2023-0164](https://github.com/Live-Hack-CVE/CVE-2023-0164)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0164">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0164">

---
## CVE-2023-0162 (2023-01-10T18:15:00)
> The CPO Companion plugin for WordPress is vulnerable to Stored Cross-Site Scripting via several of its content type settings parameters in versions up to, and including, 1.0.4 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
- [Live-Hack-CVE/CVE-2023-0162](https://github.com/Live-Hack-CVE/CVE-2023-0162)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0162">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0162">

---
## CVE-2023-0161 (2023-01-11T08:15:00)
> ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate is unused by its CNA. Notes: none.
- [Live-Hack-CVE/CVE-2023-0161](https://github.com/Live-Hack-CVE/CVE-2023-0161)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0161">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0161">

---
## CVE-2023-0158 (2023-01-17T17:15:00)
> NLnet Labs Krill supports direct access to the RRDP repository content through its built-in web server at the "/rrdp" endpoint. Prior to 0.12.1 a direct query for any existing directory under "/rrdp/", rather than an RRDP file such as "/rrdp/notification.xml" as would be expected, causes Krill to crash. If the built-in "/rrdp" endpoint is exposed directly to the internet, then malicious remote parties can cause the publication server to crash. The repository content is not affected by this, but the availability of the server and repository can cause issues if this attack is persistent and is not mitigated.
- [Live-Hack-CVE/CVE-2023-0158](https://github.com/Live-Hack-CVE/CVE-2023-0158)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0158">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0158">

---
## CVE-2023-0141 (2023-01-10T20:15:00)
> Insufficient policy enforcement in CORS in Google Chrome prior to 109.0.5414.74 allowed a remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: Low)
- [Live-Hack-CVE/CVE-2023-0141](https://github.com/Live-Hack-CVE/CVE-2023-0141)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0141">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0141">

---
## CVE-2023-0140 (2023-01-10T20:15:00)
> Inappropriate implementation in in File System API in Google Chrome on Windows prior to 109.0.5414.74 allowed a remote attacker to bypass file system restrictions via a crafted HTML page. (Chromium security severity: Low)
- [Live-Hack-CVE/CVE-2023-0140](https://github.com/Live-Hack-CVE/CVE-2023-0140)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0140">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0140">

---
## CVE-2023-0139 (2023-01-10T20:15:00)
> Insufficient validation of untrusted input in Downloads in Google Chrome on Windows prior to 109.0.5414.74 allowed a remote attacker to bypass download restrictions via a crafted HTML page. (Chromium security severity: Low)
- [Live-Hack-CVE/CVE-2023-0139](https://github.com/Live-Hack-CVE/CVE-2023-0139)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0139">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0139">

---
## CVE-2023-0138 (2023-01-10T20:15:00)
> Heap buffer overflow in libphonenumber in Google Chrome prior to 109.0.5414.74 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Low)
- [Live-Hack-CVE/CVE-2023-0138](https://github.com/Live-Hack-CVE/CVE-2023-0138)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0138">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0138">

---
## CVE-2023-0137 (2023-01-10T20:15:00)
> Heap buffer overflow in Platform Apps in Google Chrome on Chrome OS prior to 109.0.5414.74 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
- [Live-Hack-CVE/CVE-2023-0137](https://github.com/Live-Hack-CVE/CVE-2023-0137)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0137">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0137">

---
## CVE-2023-0136 (2023-01-10T20:15:00)
> Inappropriate implementation in in Fullscreen API in Google Chrome on Android prior to 109.0.5414.74 allowed a remote attacker to execute incorrect security UI via a crafted HTML page. (Chromium security severity: Medium)
- [Live-Hack-CVE/CVE-2023-0136](https://github.com/Live-Hack-CVE/CVE-2023-0136)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0136">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0136">

---
## CVE-2023-0135 (2023-01-10T20:15:00)
> Use after free in Cart in Google Chrome prior to 109.0.5414.74 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via database corruption and a crafted HTML page. (Chromium security severity: Medium)
- [Live-Hack-CVE/CVE-2023-0135](https://github.com/Live-Hack-CVE/CVE-2023-0135)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0135">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0135">

---
## CVE-2023-0134 (2023-01-10T20:15:00)
> Use after free in Cart in Google Chrome prior to 109.0.5414.74 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via database corruption and a crafted HTML page. (Chromium security severity: Medium)
- [Live-Hack-CVE/CVE-2023-0134](https://github.com/Live-Hack-CVE/CVE-2023-0134)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0134">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0134">

---
## CVE-2023-0133 (2023-01-10T20:15:00)
> Inappropriate implementation in in Permission prompts in Google Chrome on Android prior to 109.0.5414.74 allowed a remote attacker to bypass main origin permission delegation via a crafted HTML page. (Chromium security severity: Medium)
- [Live-Hack-CVE/CVE-2023-0133](https://github.com/Live-Hack-CVE/CVE-2023-0133)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0133">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0133">

---
## CVE-2023-0132 (2023-01-10T20:15:00)
> Inappropriate implementation in in Permission prompts in Google Chrome on Windows prior to 109.0.5414.74 allowed a remote attacker to force acceptance of a permission prompt via a crafted HTML page. (Chromium security severity: Medium)
- [Live-Hack-CVE/CVE-2023-0132](https://github.com/Live-Hack-CVE/CVE-2023-0132)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0132">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0132">

---
## CVE-2023-0131 (2023-01-10T20:15:00)
> Inappropriate implementation in in iframe Sandbox in Google Chrome prior to 109.0.5414.74 allowed a remote attacker to bypass file download restrictions via a crafted HTML page. (Chromium security severity: Medium)
- [Live-Hack-CVE/CVE-2023-0131](https://github.com/Live-Hack-CVE/CVE-2023-0131)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0131">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0131">

---
## CVE-2023-0130 (2023-01-10T20:15:00)
> Inappropriate implementation in in Fullscreen API in Google Chrome on Android prior to 109.0.5414.74 allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (Chromium security severity: Medium)
- [Live-Hack-CVE/CVE-2023-0130](https://github.com/Live-Hack-CVE/CVE-2023-0130)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0130">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0130">

---
## CVE-2023-0129 (2023-01-10T20:15:00)
> Heap buffer overflow in Network Service in Google Chrome prior to 109.0.5414.74 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page and specific interactions. (Chromium security severity: High)
- [Live-Hack-CVE/CVE-2023-0129](https://github.com/Live-Hack-CVE/CVE-2023-0129)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0129">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0129">

---
## CVE-2023-0128 (2023-01-10T20:15:00)
> Use after free in Overview Mode in Google Chrome on Chrome OS prior to 109.0.5414.74 allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
- [Live-Hack-CVE/CVE-2023-0128](https://github.com/Live-Hack-CVE/CVE-2023-0128)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0128">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0128">

---
## CVE-2023-0126 (2023-01-19T20:15:00)
> Pre-authentication path traversal vulnerability in SMA1000 firmware version 12.4.2, which allows an unauthenticated attacker to access arbitrary files and directories stored outside the web root directory.
- [Live-Hack-CVE/CVE-2023-0126](https://github.com/Live-Hack-CVE/CVE-2023-0126)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0126">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0126">

---
## CVE-2023-0125 (2023-01-09T21:15:00)
> A vulnerability was found in Control iD Panel. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the component Web Interface. The manipulation of the argument Nome leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-217717 was assigned to this vulnerability.
- [Live-Hack-CVE/CVE-2023-0125](https://github.com/Live-Hack-CVE/CVE-2023-0125)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0125">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0125">

---
## CVE-2023-0122 (2023-01-17T21:15:00)
> A NULL pointer dereference vulnerability in the Linux kernel NVMe functionality, in nvmet_setup_auth(), allows an attacker to perform a Pre-Auth Denial of Service (DoS) attack on a remote machine. Affected versions v6.0-rc1 to v6.0-rc3, fixed in v6.0-rc4.
- [Live-Hack-CVE/CVE-2023-0122](https://github.com/Live-Hack-CVE/CVE-2023-0122)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0122">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0122">

---
## CVE-2023-0114 (2023-01-07T09:15:00)
> A vulnerability was found in Netis Netcore Router. It has been rated as problematic. Affected by this issue is some unknown functionality of the file param.file.tgz of the component Backup Handler. The manipulation leads to cleartext storage in a file or on disk. Local access is required to approach this attack. The identifier of this vulnerability is VDB-217592.
- [Live-Hack-CVE/CVE-2023-0114](https://github.com/Live-Hack-CVE/CVE-2023-0114)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0114">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0114">

---
## CVE-2023-0113 (2023-01-07T09:15:00)
> A vulnerability was found in Netis Netcore Router. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the file param.file.tgz of the component Backup Handler. The manipulation leads to information disclosure. The attack can be launched remotely. The associated identifier of this vulnerability is VDB-217591.
- [Live-Hack-CVE/CVE-2023-0113](https://github.com/Live-Hack-CVE/CVE-2023-0113)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0113">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0113">

---
## CVE-2023-0112 (2023-01-07T04:15:00)
> Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.
- [Live-Hack-CVE/CVE-2023-0112](https://github.com/Live-Hack-CVE/CVE-2023-0112)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0112">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0112">

---
## CVE-2023-0111 (2023-01-07T04:15:00)
> Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.
- [Live-Hack-CVE/CVE-2023-0111](https://github.com/Live-Hack-CVE/CVE-2023-0111)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0111">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0111">

---
## CVE-2023-0110 (2023-01-07T04:15:00)
> Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.
- [Live-Hack-CVE/CVE-2023-0110](https://github.com/Live-Hack-CVE/CVE-2023-0110)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0110">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0110">

---
## CVE-2023-0108 (2023-01-07T04:15:00)
> Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.
- [Live-Hack-CVE/CVE-2023-0108](https://github.com/Live-Hack-CVE/CVE-2023-0108)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0108">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0108">

---
## CVE-2023-0107 (2023-01-07T04:15:00)
> Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.
- [Live-Hack-CVE/CVE-2023-0107](https://github.com/Live-Hack-CVE/CVE-2023-0107)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0107">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0107">

---
## CVE-2023-0106 (2023-01-07T04:15:00)
> Cross-site Scripting (XSS) - Stored in GitHub repository usememos/memos prior to 0.10.0.
- [Live-Hack-CVE/CVE-2023-0106](https://github.com/Live-Hack-CVE/CVE-2023-0106)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0106">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0106">

---
## CVE-2023-0088 (2023-01-05T19:15:00)
> The Swifty Page Manager plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 3.0.1. This is due to missing or incorrect nonce validation on several AJAX actions handling page creation and deletion among other things. This makes it possible for unauthenticated attackers to invoke those functions, via forged request granted they can trick a site administrator into performing an action such as clicking on a link.
- [Live-Hack-CVE/CVE-2023-0088](https://github.com/Live-Hack-CVE/CVE-2023-0088)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0088">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0088">

---
## CVE-2023-0087 (2023-01-05T19:15:00)
> The Swifty Page Manager plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the ‘spm_plugin_options_page_tree_max_width’ parameter in versions up to, and including, 3.0.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with administrator-level permissions and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. This only affects multi-site installations and installations where unfiltered_html has been disabled.
- [Live-Hack-CVE/CVE-2023-0087](https://github.com/Live-Hack-CVE/CVE-2023-0087)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0087">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0087">

---
## CVE-2023-0086 (2023-01-05T17:15:00)
> The JetWidgets for Elementor plugin for WordPress is vulnerable to Cross-Site Request Forgery in versions up to, and including, 1.0.12. This is due to missing nonce validation on the save() function. This makes it possible for unauthenticated attackers to to modify the plugin's settings via a forged request granted they can trick a site administrator into performing an action such as clicking on a link. This can be used to enable SVG uploads that could make Cross-Site Scripting possible.
- [Live-Hack-CVE/CVE-2023-0086](https://github.com/Live-Hack-CVE/CVE-2023-0086)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0086">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0086">

---
## CVE-2023-0077 (2023-01-05T10:15:00)
> Integer overflow or wraparound vulnerability in CGI component in Synology Router Manager (SRM) before 1.2.5-8227-6 and 1.3.1-9346-3 allows remote attackers to overflow buffers via unspecified vectors.
- [Live-Hack-CVE/CVE-2023-0077](https://github.com/Live-Hack-CVE/CVE-2023-0077)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0077">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0077">

---
## CVE-2023-0057 (2023-01-05T01:15:00)
> Improper Restriction of Rendered UI Layers or Frames in GitHub repository pyload/pyload prior to 0.5.0b3.dev33.
- [Live-Hack-CVE/CVE-2023-0057](https://github.com/Live-Hack-CVE/CVE-2023-0057)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0057">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0057">

---
## CVE-2023-0055 (2023-01-04T22:15:00)
> Sensitive Cookie in HTTPS Session Without 'Secure' Attribute in GitHub repository pyload/pyload prior to 0.5.0b3.dev32.
- [Live-Hack-CVE/CVE-2023-0055](https://github.com/Live-Hack-CVE/CVE-2023-0055)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0055">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0055">

---
## CVE-2023-0054 (2023-01-04T19:15:00)
> Out-of-bounds Write in GitHub repository vim/vim prior to 9.0.1145.
- [Live-Hack-CVE/CVE-2023-0054](https://github.com/Live-Hack-CVE/CVE-2023-0054)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0054">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0054">

---
## CVE-2023-0052 (2023-01-20T22:15:00)
> SAUTER Controls Nova 200–220 Series with firmware version 3.3-006 and prior and BACnetstac version 4.2.1 and prior allows the execution of commands without credentials. As Telnet and file transfer protocol (FTP) are the only protocols available for device management, an unauthorized user could access the system and modify the device configuration, which could result in the unauthorized user executing unrestricted malicious commands.
- [Live-Hack-CVE/CVE-2023-0052](https://github.com/Live-Hack-CVE/CVE-2023-0052)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0052">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0052">

---
## CVE-2023-0049 (2023-01-04T16:15:00)
> Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.1143.
- [Live-Hack-CVE/CVE-2023-0049](https://github.com/Live-Hack-CVE/CVE-2023-0049)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0049">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0049">

---
## CVE-2023-0048 (2023-01-04T14:15:00)
>  Code Injection in GitHub repository lirantal/daloradius prior to master-branch.
- [Live-Hack-CVE/CVE-2023-0048](https://github.com/Live-Hack-CVE/CVE-2023-0048)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0048">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0048">

---
## CVE-2023-0046 (2023-01-04T12:15:00)
> Improper Restriction of Names for Files and Other Resources in GitHub repository lirantal/daloradius prior to master-branch.
- [Live-Hack-CVE/CVE-2023-0046](https://github.com/Live-Hack-CVE/CVE-2023-0046)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0046">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0046">

---
## CVE-2023-0042 (2023-01-12T04:15:00)
> An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.4 prior to 15.5.7, 15.6 prior to 15.6.4, and 15.7 prior to 15.7.2. GitLab Pages allows redirection to arbitrary protocols.
- [Live-Hack-CVE/CVE-2023-0042](https://github.com/Live-Hack-CVE/CVE-2023-0042)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0042">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0042">

---
## CVE-2023-0040 (2023-01-18T19:15:00)
> Versions of Async HTTP Client prior to 1.13.2 are vulnerable to a form of targeted request manipulation called CRLF injection. This vulnerability was the result of insufficient validation of HTTP header field values before sending them to the network. Users are vulnerable if they pass untrusted data into HTTP header field values without prior sanitisation. Common use-cases here might be to place usernames from a database into HTTP header fields. This vulnerability allows attackers to inject new HTTP header fields, or entirely new requests, into the data stream. This can cause requests to be understood very differently by the remote server than was intended. In general, this is unlikely to result in data disclosure, but it can result in a number of logical errors and other misbehaviours.
- [Live-Hack-CVE/CVE-2023-0040](https://github.com/Live-Hack-CVE/CVE-2023-0040)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0040">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0040">

---
## CVE-2023-0039 (2023-01-03T15:15:00)
> The User Post Gallery - UPG plugin for WordPress is vulnerable to authorization bypass which leads to remote command execution due to the use of a nopriv AJAX action and user supplied function calls and parameters in versions up to, and including 2.19. This makes it possible for unauthenticated attackers to call arbitrary PHP functions and perform actions like adding new files that can be webshells and updating the site's options to allow anyone to register as an administrator.
- [Live-Hack-CVE/CVE-2023-0039](https://github.com/Live-Hack-CVE/CVE-2023-0039)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0039">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0039">

---
## CVE-2023-0038 (2023-01-03T14:15:00)
> The "Survey Maker – Best WordPress Survey Plugin" plugin for WordPress is vulnerable to Stored Cross-Site Scripting via survey answers in versions up to, and including, 3.1.3 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts when submitting quizzes that will execute whenever a user accesses the submissions page.
- [Live-Hack-CVE/CVE-2023-0038](https://github.com/Live-Hack-CVE/CVE-2023-0038)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0038">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0038">

---
## CVE-2023-0036 (2023-01-09T03:15:00)
> platform_callback_stub in misc subsystem within OpenHarmony-v3.0.5 and prior versions has an authentication bypass vulnerability which allows an "SA relay attack".Local attackers can bypass authentication and attack other SAs with high privilege.
- [Live-Hack-CVE/CVE-2023-0036](https://github.com/Live-Hack-CVE/CVE-2023-0036)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0036">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0036">

---
## CVE-2023-0035 (2023-01-09T03:15:00)
> softbus_client_stub in communication subsystem within OpenHarmony-v3.0.5 and prior versions has an authentication bypass vulnerability which allows an "SA relay attack".Local attackers can bypass authentication and attack other SAs with high privilege.
- [Live-Hack-CVE/CVE-2023-0035](https://github.com/Live-Hack-CVE/CVE-2023-0035)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0035">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0035">

---
## CVE-2023-0029 (2023-01-01T14:15:00)
> A vulnerability was found in Multilaser RE708 RE1200R4GC-2T2R-V3_v3411b_MUL029B. It has been rated as problematic. This issue affects some unknown processing of the component Telnet Service. The manipulation leads to denial of service. The attack may be initiated remotely. The identifier VDB-217169 was assigned to this vulnerability.
- [Live-Hack-CVE/CVE-2023-0029](https://github.com/Live-Hack-CVE/CVE-2023-0029)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0029">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0029">

---
## CVE-2023-0028 (2023-01-01T01:15:00)
> Cross-site Scripting (XSS) - Stored in GitHub repository linagora/twake prior to 2023.Q1.1200+.
- [Live-Hack-CVE/CVE-2023-0028](https://github.com/Live-Hack-CVE/CVE-2023-0028)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0028">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0028">

---
## CVE-2023-0023 (2023-01-10T04:15:00)
> In SAP Bank Account Management (Manage Banks) application, when a user clicks a smart link to navigate to another app, personal data is shown directly in the URL. They might get captured in log files, bookmarks, and so on disclosing sensitive data of the application.
- [Live-Hack-CVE/CVE-2023-0023](https://github.com/Live-Hack-CVE/CVE-2023-0023)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0023">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0023">

---
## CVE-2023-0022 (2023-01-10T04:15:00)
> SAP BusinessObjects Business Intelligence Analysis edition for OLAP allows an authenticated attacker to inject malicious code that can be executed by the application over the network. On successful exploitation, an attacker can perform operations that may completely compromise the application causing a high impact on the confidentiality, integrity, and availability of the application.
- [Live-Hack-CVE/CVE-2023-0022](https://github.com/Live-Hack-CVE/CVE-2023-0022)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0022">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0022">

---
## CVE-2023-0018 (2023-01-10T04:15:00)
> Due to improper input sanitization of user-controlled input in SAP BusinessObjects Business Intelligence Platform CMC application - versions 420, and 430, an attacker with basic user-level privileges can modify/upload crystal reports containing a malicious payload. Once these reports are viewable, anyone who opens those reports would be susceptible to stored XSS attacks. As a result of the attack, information maintained in the victim's web browser can be read, modified, and sent to the attacker.
- [Live-Hack-CVE/CVE-2023-0018](https://github.com/Live-Hack-CVE/CVE-2023-0018)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0018">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0018">

---
## CVE-2023-0017 (2023-01-10T04:15:00)
> An unauthenticated attacker in SAP NetWeaver AS for Java - version 7.50, due to improper access control, can attach to an open interface and make use of an open naming and directory API to access services which can be used to perform unauthorized operations affecting users and data on the current system. This could allow the attacker to have full read access to user data, make modifications to user data, and make services within the system unavailable.
- [Live-Hack-CVE/CVE-2023-0017](https://github.com/Live-Hack-CVE/CVE-2023-0017)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0017">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0017">

---
## CVE-2023-0016 (2023-01-10T04:15:00)
> SAP BPC MS 10.0 - version 810, allows an unauthorized attacker to execute crafted database queries. The exploitation of this issue could lead to SQL injection vulnerability and could allow an attacker to access, modify, and/or delete data from the backend database.
- [Live-Hack-CVE/CVE-2023-0016](https://github.com/Live-Hack-CVE/CVE-2023-0016)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0016">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0016">

---
## CVE-2023-0015 (2023-01-10T04:15:00)
> In SAP BusinessObjects Business Intelligence Platform (Web Intelligence user interface) - version 420, some calls return json with wrong content type in the header of the response. As a result, a custom application that calls directly the jsp of Web Intelligence DHTML may be vulnerable to XSS attacks. On successful exploitation an attacker can cause limited impact on confidentiality and integrity of the application.
- [Live-Hack-CVE/CVE-2023-0015](https://github.com/Live-Hack-CVE/CVE-2023-0015)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0015">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0015">

---
## CVE-2023-0014 (2023-01-10T04:15:00)
> SAP NetWeaver ABAP Server and ABAP Platform - versions SAP_BASIS 700, 701, 702, 710, 711, 730, 731, 740, 750, 751, 752, 753, 754, 755, 756, 757, KERNEL 7.22, 7.53, 7.77, 7.81, 7.85, 7.89, KRNL64UC 7.22, 7.22EXT, 7.53, KRNL64NUC 7.22, 7.22EXT, creates information about system identity in an ambiguous format. This could lead to capture-replay vulnerability and may be exploited by malicious users to obtain illegitimate access to the system.
- [Live-Hack-CVE/CVE-2023-0014](https://github.com/Live-Hack-CVE/CVE-2023-0014)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0014">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0014">

---
## CVE-2023-0013 (2023-01-10T03:15:00)
> The ABAP Keyword Documentation of SAP NetWeaver Application Server - versions 702, 731, 740, 750, 751, 752, 753, 754, 755, 756, 757, for ABAP and ABAP Platform does not sufficiently encode user-controlled inputs, resulting in Cross-Site Scripting (XSS) vulnerability. On successful exploitation an attacker can cause limited impact on confidentiality and integrity of the application.
- [Live-Hack-CVE/CVE-2023-0013](https://github.com/Live-Hack-CVE/CVE-2023-0013)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0013">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0013">

---
## CVE-2023-0012 (2023-01-10T03:15:00)
> In SAP Host Agent (Windows) - versions 7.21, 7.22, an attacker who gains local membership to SAP_LocalAdmin could be able to replace executables with a malicious file that will be started under a privileged account. Note that by default all user members of SAP_LocaAdmin are denied the ability to logon locally by security policy so that this can only occur if the system has already been compromised.
- [Live-Hack-CVE/CVE-2023-0012](https://github.com/Live-Hack-CVE/CVE-2023-0012)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0012">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0012">
