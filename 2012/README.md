# 2012 List

---
## CVE-2012-6704 (2016-12-28T07:59:00)
> The sock_setsockopt function in net/core/sock.c in the Linux kernel before 3.5 mishandles negative values of sk_sndbuf and sk_rcvbuf, which allows local users to cause a denial of service (memory corruption and system crash) or possibly have unspecified other impact by leveraging the CAP_NET_ADMIN capability for a crafted setsockopt system call with the (1) SO_SNDBUF or (2) SO_RCVBUF option.
- [Live-Hack-CVE/CVE-2012-6704](https://github.com/Live-Hack-CVE/CVE-2012-6704)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-6704">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-6704">

---
## CVE-2012-6703 (2016-06-29T14:10:00)
> Integer overflow in the snd_compr_allocate_buffer function in sound/core/compress_offload.c in the ALSA subsystem in the Linux kernel before 3.6-rc6-next-20120917 allows local users to cause a denial of service (insufficient memory allocation) or possibly have unspecified other impact via a crafted SNDRV_COMPRESS_SET_PARAMS ioctl call.
- [Live-Hack-CVE/CVE-2012-6703](https://github.com/Live-Hack-CVE/CVE-2012-6703)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-6703">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-6703">

---
## CVE-2012-6701 (2016-05-02T10:59:00)
> Integer overflow in fs/aio.c in the Linux kernel before 3.4.1 allows local users to cause a denial of service or possibly have unspecified other impact via a large AIO iovec.
- [Live-Hack-CVE/CVE-2012-6701](https://github.com/Live-Hack-CVE/CVE-2012-6701)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-6701">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-6701">

---
## CVE-2012-6689 (2016-05-02T10:59:00)
> The netlink_sendmsg function in net/netlink/af_netlink.c in the Linux kernel before 3.5.5 does not validate the dst_pid field, which allows local users to have an unspecified impact by spoofing Netlink messages.
- [Live-Hack-CVE/CVE-2012-6689](https://github.com/Live-Hack-CVE/CVE-2012-6689)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-6689">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-6689">

---
## CVE-2012-6638 (2014-02-15T14:57:00)
> The tcp_rcv_state_process function in net/ipv4/tcp_input.c in the Linux kernel before 3.2.24 allows remote attackers to cause a denial of service (kernel resource consumption) via a flood of SYN+FIN TCP packets, a different vulnerability than CVE-2012-2663.
- [Live-Hack-CVE/CVE-2012-6638](https://github.com/Live-Hack-CVE/CVE-2012-6638)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-6638">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-6638">

---
## CVE-2012-5664 (2012-12-26T20:55:00)
> ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2012-6496, CVE-2012-6497. Reason: this candidate was intended for one issue, but the candidate was publicly used to label concerns about multiple products. Notes: All CVE users should consult CVE-2012-6496 and CVE-2012-6497 to determine which ID is appropriate. All references and descriptions in this candidate have been removed to prevent accidental usage.
- [Live-Hack-CVE/CVE-2012-5664](https://github.com/Live-Hack-CVE/CVE-2012-5664)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-5664">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-5664">
- [phusion/rails-cve-2012-5664-test](https://github.com/phusion/rails-cve-2012-5664-test)	<img alt="forks" src="https://img.shields.io/github/forks/phusion/rails-cve-2012-5664-test">	<img alt="stars" src="https://img.shields.io/github/stars/phusion/rails-cve-2012-5664-test">

---
## CVE-2012-5613 (2012-12-03T12:49:00)
> ** DISPUTED ** MySQL 5.5.19 and possibly other versions, and MariaDB 5.5.28a and possibly other versions, when configured to assign the FILE privilege to users who should not have administrative privileges, allows remote authenticated users to gain privileges by leveraging the FILE privilege to create files as the MySQL administrator. NOTE: the vendor disputes this issue, stating that this is only a vulnerability when the administrator does not follow recommendations in the product's installation documentation. NOTE: it could be argued that this should not be included in CVE because it is a configuration issue.
- [Live-Hack-CVE/CVE-2012-5613](https://github.com/Live-Hack-CVE/CVE-2012-5613)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-5613">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-5613">
- [w4fz5uck5/UDFPwn-CVE-2012-5613](https://github.com/w4fz5uck5/UDFPwn-CVE-2012-5613)	<img alt="forks" src="https://img.shields.io/github/forks/w4fz5uck5/UDFPwn-CVE-2012-5613">	<img alt="stars" src="https://img.shields.io/github/stars/w4fz5uck5/UDFPwn-CVE-2012-5613">
- [Hood3dRob1n/MySQL-Fu.rb](https://github.com/Hood3dRob1n/MySQL-Fu.rb)	<img alt="forks" src="https://img.shields.io/github/forks/Hood3dRob1n/MySQL-Fu.rb">	<img alt="stars" src="https://img.shields.io/github/stars/Hood3dRob1n/MySQL-Fu.rb">

---
## CVE-2012-5601 (2012-12-05T11:57:00)
> ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2012-6055. Reason: This candidate is a reservation duplicate of CVE-2012-6055. Notes: All CVE users should reference CVE-2012-6055 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.
- [Live-Hack-CVE/CVE-2012-5601](https://github.com/Live-Hack-CVE/CVE-2012-5601)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-5601">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-5601">

---
## CVE-2012-5600 (2012-12-05T11:57:00)
> ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2012-6062. Reason: This candidate is a reservation duplicate of CVE-2012-6062. Notes: All CVE users should reference CVE-2012-6062 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.
- [Live-Hack-CVE/CVE-2012-5600](https://github.com/Live-Hack-CVE/CVE-2012-5600)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-5600">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-5600">

---
## CVE-2012-5599 (2012-12-05T11:57:00)
> ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2012-6061. Reason: This candidate is a reservation duplicate of CVE-2012-6061. Notes: All CVE users should reference CVE-2012-6061 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.
- [Live-Hack-CVE/CVE-2012-5599](https://github.com/Live-Hack-CVE/CVE-2012-5599)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-5599">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-5599">

---
## CVE-2012-5598 (2012-12-05T11:57:00)
> ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2012-6060. Reason: This candidate is a reservation duplicate of CVE-2012-6060. Notes: All CVE users should reference CVE-2012-6060 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.
- [Live-Hack-CVE/CVE-2012-5598](https://github.com/Live-Hack-CVE/CVE-2012-5598)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-5598">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-5598">

---
## CVE-2012-5597 (2012-12-05T11:57:00)
> ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2012-6059. Reason: This candidate is a reservation duplicate of CVE-2012-6059. Notes: All CVE users should reference CVE-2012-6059 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.
- [Live-Hack-CVE/CVE-2012-5597](https://github.com/Live-Hack-CVE/CVE-2012-5597)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-5597">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-5597">

---
## CVE-2012-5596 (2012-12-05T11:57:00)
> ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2012-6057. Reason: This candidate is a reservation duplicate of CVE-2012-6057. Notes: All CVE users should reference CVE-2012-6057 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.
- [Live-Hack-CVE/CVE-2012-5596](https://github.com/Live-Hack-CVE/CVE-2012-5596)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-5596">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-5596">

---
## CVE-2012-5595 (2012-12-05T11:57:00)
> ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2012-6056. Reason: This candidate is a reservation duplicate of CVE-2012-6056. Notes: All CVE users should reference CVE-2012-6056 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.
- [Live-Hack-CVE/CVE-2012-5595](https://github.com/Live-Hack-CVE/CVE-2012-5595)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-5595">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-5595">

---
## CVE-2012-5594 (2012-12-05T11:57:00)
> ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2012-6054. Reason: This candidate is a reservation duplicate of CVE-2012-6054. Notes: All CVE users should reference CVE-2012-6054 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.
- [Live-Hack-CVE/CVE-2012-5594](https://github.com/Live-Hack-CVE/CVE-2012-5594)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-5594">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-5594">

---
## CVE-2012-5593 (2012-12-05T11:57:00)
> ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2012-6053. Reason: This candidate is a reservation duplicate of CVE-2012-6053. Notes: All CVE users should reference CVE-2012-6053 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.
- [Live-Hack-CVE/CVE-2012-5593](https://github.com/Live-Hack-CVE/CVE-2012-5593)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-5593">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-5593">

---
## CVE-2012-5592 (2012-12-05T11:57:00)
> ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2012-6052. Reason: This candidate is a reservation duplicate of CVE-2012-6052. Notes: All CVE users should reference CVE-2012-6052 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.
- [Live-Hack-CVE/CVE-2012-5592](https://github.com/Live-Hack-CVE/CVE-2012-5592)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-5592">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-5592">

---
## CVE-2012-5519 (2012-11-20T00:55:00)
> CUPS 1.4.4, when running in certain Linux distributions such as Debian GNU/Linux, stores the web interface administrator key in /var/run/cups/certs/0 using certain permissions, which allows local users in the lpadmin group to read or write arbitrary files as root by leveraging the web interface.
- [p1ckzi/CVE-2012-5519](https://github.com/p1ckzi/CVE-2012-5519)	<img alt="forks" src="https://img.shields.io/github/forks/p1ckzi/CVE-2012-5519">	<img alt="stars" src="https://img.shields.io/github/stars/p1ckzi/CVE-2012-5519">

---
## CVE-2012-5475 (2012-11-16T12:24:00)
> ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2012-5881, CVE-2012-5882, CVE-2012-5883. Reason: This candidate is a duplicate of CVE-2012-5881, CVE-2012-5882, and CVE-2012-5883. Notes: All CVE users should reference one or more of CVE-2012-5881, CVE-2012-5882, and CVE-2012-5883 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.
- [Live-Hack-CVE/CVE-2012-5475](https://github.com/Live-Hack-CVE/CVE-2012-5475)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-5475">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-5475">

---
## CVE-2012-4681 (2012-08-28T00:55:00)
> Multiple vulnerabilities in the Java Runtime Environment (JRE) component in Oracle Java SE 7 Update 6 and earlier allow remote attackers to execute arbitrary code via a crafted applet that bypasses SecurityManager restrictions by (1) using com.sun.beans.finder.ClassFinder.findClass and leveraging an exception with the forName method to access restricted classes from arbitrary packages such as sun.awt.SunToolkit, then (2) using "reflection with a trusted immediate caller" to leverage the getField method to access and modify private fields, as exploited in the wild in August 2012 using Gondzz.class and Gondvv.class.
- [Live-Hack-CVE/CVE-2012-4681](https://github.com/Live-Hack-CVE/CVE-2012-4681)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-4681">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-4681">
- [Live-Hack-CVE/CVE-2012-4681](https://github.com/Live-Hack-CVE/CVE-2012-4681)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-4681">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-4681">
- [ZH3FENG/PoCs-CVE_2012_4681](https://github.com/ZH3FENG/PoCs-CVE_2012_4681)	<img alt="forks" src="https://img.shields.io/github/forks/ZH3FENG/PoCs-CVE_2012_4681">	<img alt="stars" src="https://img.shields.io/github/stars/ZH3FENG/PoCs-CVE_2012_4681">
- [benjholla/CVE-2012-4681-Armoring](https://github.com/benjholla/CVE-2012-4681-Armoring)	<img alt="forks" src="https://img.shields.io/github/forks/benjholla/CVE-2012-4681-Armoring">	<img alt="stars" src="https://img.shields.io/github/stars/benjholla/CVE-2012-4681-Armoring">

---
## CVE-2012-4388 (2012-09-07T22:55:00)
> The sapi_header_op function in main/SAPI.c in PHP 5.4.0RC2 through 5.4.0 does not properly determine a pointer during checks for %0D sequences (aka carriage return characters), which allows remote attackers to bypass an HTTP response-splitting protection mechanism via a crafted URL, related to improper interaction between the PHP header function and certain browsers, as demonstrated by Internet Explorer and Google Chrome.  NOTE: this vulnerability exists because of an incorrect fix for CVE-2011-1398.
- [Live-Hack-CVE/CVE-2012-4388](https://github.com/Live-Hack-CVE/CVE-2012-4388)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-4388">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-4388">

---
## CVE-2012-4244 (2012-09-14T10:33:00)
> ISC BIND 9.x before 9.7.6-P3, 9.8.x before 9.8.3-P3, 9.9.x before 9.9.1-P3, and 9.4-ESV and 9.6-ESV before 9.6-ESV-R7-P3 allows remote attackers to cause a denial of service (assertion failure and named daemon exit) via a query for a long resource record.
- [Live-Hack-CVE/CVE-2012-4244](https://github.com/Live-Hack-CVE/CVE-2012-4244)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-4244">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-4244">
- [Live-Hack-CVE/CVE-2012-4244](https://github.com/Live-Hack-CVE/CVE-2012-4244)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-4244">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-4244">

---
## CVE-2012-3400 (2012-10-03T11:02:00)
> Heap-based buffer overflow in the udf_load_logicalvol function in fs/udf/super.c in the Linux kernel before 3.4.5 allows remote attackers to cause a denial of service (system crash) or possibly have unspecified other impact via a crafted UDF filesystem.
- [Live-Hack-CVE/CVE-2012-3400](https://github.com/Live-Hack-CVE/CVE-2012-3400)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-3400">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-3400">

---
## CVE-2012-3386 (2012-08-07T21:55:00)
> It was found that the distcheck rule in Automake-generated Makefiles made a directory world-writable when preparing source archives. If a malicious, local user could access this directory, they could execute arbitrary code with the privileges of the user running "make distcheck".
- [Live-Hack-CVE/CVE-2012-3386](https://github.com/Live-Hack-CVE/CVE-2012-3386)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-3386">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-3386">

---
## CVE-2012-3287 (2012-06-13T19:55:00)
> Poul-Henning Kamp md5crypt has insufficient algorithmic complexity and a consequently short runtime, which makes it easier for context-dependent attackers to discover cleartext passwords via a brute-force attack, as demonstrated by an attack using GPU hardware.
- [Live-Hack-CVE/CVE-2012-3287](https://github.com/Live-Hack-CVE/CVE-2012-3287)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-3287">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-3287">

---
## CVE-2012-2982 (2012-09-11T18:55:00)
> file/show.cgi in Webmin 1.590 and earlier allows remote authenticated users to execute arbitrary commands via an invalid character in a pathname, as demonstrated by a | (pipe) character.
- [0xF331-D3AD/CVE-2012-2982](https://github.com/0xF331-D3AD/CVE-2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/0xF331-D3AD/CVE-2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/0xF331-D3AD/CVE-2012-2982">
- [0xTas/CVE-2012-2982](https://github.com/0xTas/CVE-2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/0xTas/CVE-2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/0xTas/CVE-2012-2982">
- [R00tendo/CVE-2012-2982](https://github.com/R00tendo/CVE-2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/R00tendo/CVE-2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/R00tendo/CVE-2012-2982">
- [blu3ming/CVE-2012-2982](https://github.com/blu3ming/CVE-2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/blu3ming/CVE-2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/blu3ming/CVE-2012-2982">
- [wizardy0ga/CVE_2012-2982](https://github.com/wizardy0ga/CVE_2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/wizardy0ga/CVE_2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/wizardy0ga/CVE_2012-2982">
- [JohnHammond/CVE-2012-2982](https://github.com/JohnHammond/CVE-2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/JohnHammond/CVE-2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/JohnHammond/CVE-2012-2982">
- [Ari-Weinberg/CVE-2012-2982](https://github.com/Ari-Weinberg/CVE-2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/Ari-Weinberg/CVE-2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/Ari-Weinberg/CVE-2012-2982">
- [AlexJS6/CVE-2012-2982_Python](https://github.com/AlexJS6/CVE-2012-2982_Python)	<img alt="forks" src="https://img.shields.io/github/forks/AlexJS6/CVE-2012-2982_Python">	<img alt="stars" src="https://img.shields.io/github/stars/AlexJS6/CVE-2012-2982_Python">
- [cd6629/CVE-2012-2982-Python-PoC](https://github.com/cd6629/CVE-2012-2982-Python-PoC)	<img alt="forks" src="https://img.shields.io/github/forks/cd6629/CVE-2012-2982-Python-PoC">	<img alt="stars" src="https://img.shields.io/github/stars/cd6629/CVE-2012-2982-Python-PoC">
- [OstojaOfficial/CVE-2012-2982](https://github.com/OstojaOfficial/CVE-2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/OstojaOfficial/CVE-2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/OstojaOfficial/CVE-2012-2982">
- [Dawnn3619/CVE-2012-2982](https://github.com/Dawnn3619/CVE-2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/Dawnn3619/CVE-2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/Dawnn3619/CVE-2012-2982">
- [LeDucKhiem/CVE-2012-2982](https://github.com/LeDucKhiem/CVE-2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/LeDucKhiem/CVE-2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/LeDucKhiem/CVE-2012-2982">

---
## CVE-2012-2661 (2012-06-22T14:55:00)
> The Active Record component in Ruby on Rails 3.0.x before 3.0.13, 3.1.x before 3.1.5, and 3.2.x before 3.2.4 does not properly implement the passing of request data to a where method in an ActiveRecord class, which allows remote attackers to conduct certain SQL injection attacks via nested query parameters that leverage unintended recursion, a related issue to CVE-2012-2695.
- [Blackyguy/-CVE-2012-2661-ActiveRecord-SQL-injection-](https://github.com/Blackyguy/-CVE-2012-2661-ActiveRecord-SQL-injection-)	<img alt="forks" src="https://img.shields.io/github/forks/Blackyguy/-CVE-2012-2661-ActiveRecord-SQL-injection-">	<img alt="stars" src="https://img.shields.io/github/stars/Blackyguy/-CVE-2012-2661-ActiveRecord-SQL-injection-">

---
## CVE-2012-2658 (2012-08-31T18:55:00)
> ** DISPUTED ** Buffer overflow in the SQLDriverConnect function in unixODBC 2.3.1 allows local users to cause a denial of service (crash) via a long string in the DRIVER option. NOTE: this issue might not be a vulnerability, since the ability to set this option typically implies that the attacker already has legitimate access to cause a DoS or execute code, and therefore the issue would not cross privilege boundaries. There may be limited attack scenarios if isql command-line options are exposed to an attacker, although it seems likely that other, more serious issues would also be exposed, and this issue might not cross privilege boundaries in that context.
- [Live-Hack-CVE/CVE-2012-2658](https://github.com/Live-Hack-CVE/CVE-2012-2658)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-2658">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-2658">

---
## CVE-2012-2657 (2012-08-31T18:55:00)
> ** DISPUTED ** Buffer overflow in the SQLDriverConnect function in unixODBC 2.0.10, 2.3.1, and earlier allows local users to cause a denial of service (crash) via a long string in the FILEDSN option. NOTE: this issue might not be a vulnerability, since the ability to set this option typically implies that the attacker already has legitimate access to cause a DoS or execute code, and therefore the issue would not cross privilege boundaries. There may be limited attack scenarios if isql command-line options are exposed to an attacker, although it seems likely that other, more serious issues would also be exposed, and this issue might not cross privilege boundaries in that context.
- [Live-Hack-CVE/CVE-2012-2657](https://github.com/Live-Hack-CVE/CVE-2012-2657)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-2657">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-2657">

---
## CVE-2012-2386 (2012-07-07T10:21:00)
> CVE-2012-2386 php: Integer overflow leading to heap-buffer overflow in the Phar extension
- [Live-Hack-CVE/CVE-2012-2386](https://github.com/Live-Hack-CVE/CVE-2012-2386)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-2386">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-2386">

---
## CVE-2012-2128 (2012-08-27T21:55:00)
> ** DISPUTED ** Cross-site request forgery (CSRF) vulnerability in doku.php in DokuWiki 2012-01-25 Angua allows remote attackers to hijack the authentication of administrators for requests that add arbitrary users. NOTE: this issue has been disputed by the vendor, who states that it is resultant from CVE-2012-2129: "the exploit code simply uses the XSS hole to extract a valid CSRF token."
- [Live-Hack-CVE/CVE-2012-2128](https://github.com/Live-Hack-CVE/CVE-2012-2128)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-2128">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-2128">

---
## CVE-2012-2012 (2012-06-29T22:55:00)
> HP System Management Homepage (SMH) before 7.1.1 does not have an off autocomplete attribute for unspecified form fields, which makes it easier for remote attackers to obtain access by leveraging an unattended workstation.
- [hello123body/CVE-2012-2012](https://github.com/hello123body/CVE-2012-2012)	<img alt="forks" src="https://img.shields.io/github/forks/hello123body/CVE-2012-2012">	<img alt="stars" src="https://img.shields.io/github/stars/hello123body/CVE-2012-2012">
- [R00tendo/CVE-2012-2982](https://github.com/R00tendo/CVE-2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/R00tendo/CVE-2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/R00tendo/CVE-2012-2982">
- [0xTas/CVE-2012-2982](https://github.com/0xTas/CVE-2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/0xTas/CVE-2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/0xTas/CVE-2012-2982">
- [irsl/CVE-2022-20128](https://github.com/irsl/CVE-2022-20128)	<img alt="forks" src="https://img.shields.io/github/forks/irsl/CVE-2022-20128">	<img alt="stars" src="https://img.shields.io/github/stars/irsl/CVE-2022-20128">
- [Trinadh465/packages_apps_Bluetooth_AOSP10_r33_CVE-2022-20126](https://github.com/Trinadh465/packages_apps_Bluetooth_AOSP10_r33_CVE-2022-20126)	<img alt="forks" src="https://img.shields.io/github/forks/Trinadh465/packages_apps_Bluetooth_AOSP10_r33_CVE-2022-20126">	<img alt="stars" src="https://img.shields.io/github/stars/Trinadh465/packages_apps_Bluetooth_AOSP10_r33_CVE-2022-20126">
- [Sunqiz/CVE-2012-0158-reproduction](https://github.com/Sunqiz/CVE-2012-0158-reproduction)	<img alt="forks" src="https://img.shields.io/github/forks/Sunqiz/CVE-2012-0158-reproduction">	<img alt="stars" src="https://img.shields.io/github/stars/Sunqiz/CVE-2012-0158-reproduction">
- [theykillmeslowly/CVE-2012-1823](https://github.com/theykillmeslowly/CVE-2012-1823)	<img alt="forks" src="https://img.shields.io/github/forks/theykillmeslowly/CVE-2012-1823">	<img alt="stars" src="https://img.shields.io/github/stars/theykillmeslowly/CVE-2012-1823">
- [Blackyguy/-CVE-2012-2661-ActiveRecord-SQL-injection-](https://github.com/Blackyguy/-CVE-2012-2661-ActiveRecord-SQL-injection-)	<img alt="forks" src="https://img.shields.io/github/forks/Blackyguy/-CVE-2012-2661-ActiveRecord-SQL-injection-">	<img alt="stars" src="https://img.shields.io/github/stars/Blackyguy/-CVE-2012-2661-ActiveRecord-SQL-injection-">
- [nidhi7598/Frameworks_base_AOSP10_r33__CVE-2022-20124-](https://github.com/nidhi7598/Frameworks_base_AOSP10_r33__CVE-2022-20124-)	<img alt="forks" src="https://img.shields.io/github/forks/nidhi7598/Frameworks_base_AOSP10_r33__CVE-2022-20124-">	<img alt="stars" src="https://img.shields.io/github/stars/nidhi7598/Frameworks_base_AOSP10_r33__CVE-2022-20124-">
- [p1ckzi/CVE-2012-5519](https://github.com/p1ckzi/CVE-2012-5519)	<img alt="forks" src="https://img.shields.io/github/forks/p1ckzi/CVE-2012-5519">	<img alt="stars" src="https://img.shields.io/github/stars/p1ckzi/CVE-2012-5519">
- [0xF331-D3AD/CVE-2012-2982](https://github.com/0xF331-D3AD/CVE-2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/0xF331-D3AD/CVE-2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/0xF331-D3AD/CVE-2012-2982">
- [Snip3R69/CVE-2013-4710-WebView-RCE-Vulnerability](https://github.com/Snip3R69/CVE-2013-4710-WebView-RCE-Vulnerability)	<img alt="forks" src="https://img.shields.io/github/forks/Snip3R69/CVE-2013-4710-WebView-RCE-Vulnerability">	<img alt="stars" src="https://img.shields.io/github/stars/Snip3R69/CVE-2013-4710-WebView-RCE-Vulnerability">
- [0xkasra/CVE-2012-4869](https://github.com/0xkasra/CVE-2012-4869)	<img alt="forks" src="https://img.shields.io/github/forks/0xkasra/CVE-2012-4869">	<img alt="stars" src="https://img.shields.io/github/stars/0xkasra/CVE-2012-4869">
- [blu3ming/CVE-2012-2982](https://github.com/blu3ming/CVE-2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/blu3ming/CVE-2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/blu3ming/CVE-2012-2982">
- [ExploitCN/CVE-2012-1876-win7_x86_and_win7x64](https://github.com/ExploitCN/CVE-2012-1876-win7_x86_and_win7x64)	<img alt="forks" src="https://img.shields.io/github/forks/ExploitCN/CVE-2012-1876-win7_x86_and_win7x64">	<img alt="stars" src="https://img.shields.io/github/stars/ExploitCN/CVE-2012-1876-win7_x86_and_win7x64">
- [Anonymous-Family/CVE-2017-0213](https://github.com/Anonymous-Family/CVE-2017-0213)	<img alt="forks" src="https://img.shields.io/github/forks/Anonymous-Family/CVE-2017-0213">	<img alt="stars" src="https://img.shields.io/github/stars/Anonymous-Family/CVE-2017-0213">
- [AndrewTrube/CVE-2012-2593](https://github.com/AndrewTrube/CVE-2012-2593)	<img alt="forks" src="https://img.shields.io/github/forks/AndrewTrube/CVE-2012-2593">	<img alt="stars" src="https://img.shields.io/github/stars/AndrewTrube/CVE-2012-2593">
- [RobertoLeonFR-ES/Exploit-Win32.CVE-2012-0158.F.doc](https://github.com/RobertoLeonFR-ES/Exploit-Win32.CVE-2012-0158.F.doc)	<img alt="forks" src="https://img.shields.io/github/forks/RobertoLeonFR-ES/Exploit-Win32.CVE-2012-0158.F.doc">	<img alt="stars" src="https://img.shields.io/github/stars/RobertoLeonFR-ES/Exploit-Win32.CVE-2012-0158.F.doc">
- [sh7alward/CVE-20121-34527-nightmare](https://github.com/sh7alward/CVE-20121-34527-nightmare)	<img alt="forks" src="https://img.shields.io/github/forks/sh7alward/CVE-20121-34527-nightmare">	<img alt="stars" src="https://img.shields.io/github/stars/sh7alward/CVE-20121-34527-nightmare">
- [wizardy0ga/CVE_2012-2982](https://github.com/wizardy0ga/CVE_2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/wizardy0ga/CVE_2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/wizardy0ga/CVE_2012-2982">
- [JohnHammond/CVE-2012-2982](https://github.com/JohnHammond/CVE-2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/JohnHammond/CVE-2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/JohnHammond/CVE-2012-2982">
- [bitc0de/Elastix-Remote-Code-Execution](https://github.com/bitc0de/Elastix-Remote-Code-Execution)	<img alt="forks" src="https://img.shields.io/github/forks/bitc0de/Elastix-Remote-Code-Execution">	<img alt="stars" src="https://img.shields.io/github/stars/bitc0de/Elastix-Remote-Code-Execution">
- [dja2TaqkGEEfA45/CVE-2012-1870](https://github.com/dja2TaqkGEEfA45/CVE-2012-1870)	<img alt="forks" src="https://img.shields.io/github/forks/dja2TaqkGEEfA45/CVE-2012-1870">	<img alt="stars" src="https://img.shields.io/github/stars/dja2TaqkGEEfA45/CVE-2012-1870">
- [l-iberty/cve-2012-1889](https://github.com/l-iberty/cve-2012-1889)	<img alt="forks" src="https://img.shields.io/github/forks/l-iberty/cve-2012-1889">	<img alt="stars" src="https://img.shields.io/github/stars/l-iberty/cve-2012-1889">
- [Ari-Weinberg/CVE-2012-2982](https://github.com/Ari-Weinberg/CVE-2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/Ari-Weinberg/CVE-2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/Ari-Weinberg/CVE-2012-2982">
- [AlexJS6/CVE-2012-2982_Python](https://github.com/AlexJS6/CVE-2012-2982_Python)	<img alt="forks" src="https://img.shields.io/github/forks/AlexJS6/CVE-2012-2982_Python">	<img alt="stars" src="https://img.shields.io/github/stars/AlexJS6/CVE-2012-2982_Python">
- [anmolksachan/MS12-020](https://github.com/anmolksachan/MS12-020)	<img alt="forks" src="https://img.shields.io/github/forks/anmolksachan/MS12-020">	<img alt="stars" src="https://img.shields.io/github/stars/anmolksachan/MS12-020">
- [clic-kbait/A2SV--SSL-VUL-Scan](https://github.com/clic-kbait/A2SV--SSL-VUL-Scan)	<img alt="forks" src="https://img.shields.io/github/forks/clic-kbait/A2SV--SSL-VUL-Scan">	<img alt="stars" src="https://img.shields.io/github/stars/clic-kbait/A2SV--SSL-VUL-Scan">
- [cd6629/CVE-2012-2982-Python-PoC](https://github.com/cd6629/CVE-2012-2982-Python-PoC)	<img alt="forks" src="https://img.shields.io/github/forks/cd6629/CVE-2012-2982-Python-PoC">	<img alt="stars" src="https://img.shields.io/github/stars/cd6629/CVE-2012-2982-Python-PoC">
- [OstojaOfficial/CVE-2012-2982](https://github.com/OstojaOfficial/CVE-2012-2982)	<img alt="forks" src="https://img.shields.io/github/forks/OstojaOfficial/CVE-2012-2982">	<img alt="stars" src="https://img.shields.io/github/stars/OstojaOfficial/CVE-2012-2982">

---
## CVE-2012-1823 (2012-05-11T10:15:00)
> sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.
- [theykillmeslowly/CVE-2012-1823](https://github.com/theykillmeslowly/CVE-2012-1823)	<img alt="forks" src="https://img.shields.io/github/forks/theykillmeslowly/CVE-2012-1823">	<img alt="stars" src="https://img.shields.io/github/stars/theykillmeslowly/CVE-2012-1823">
- [cyberharsh/PHP_CVE-2012-1823](https://github.com/cyberharsh/PHP_CVE-2012-1823)	<img alt="forks" src="https://img.shields.io/github/forks/cyberharsh/PHP_CVE-2012-1823">	<img alt="stars" src="https://img.shields.io/github/stars/cyberharsh/PHP_CVE-2012-1823">
- [Unix13/metasploitable2](https://github.com/Unix13/metasploitable2)	<img alt="forks" src="https://img.shields.io/github/forks/Unix13/metasploitable2">	<img alt="stars" src="https://img.shields.io/github/stars/Unix13/metasploitable2">
- [tardummy01/oscp_scripts-1](https://github.com/tardummy01/oscp_scripts-1)	<img alt="forks" src="https://img.shields.io/github/forks/tardummy01/oscp_scripts-1">	<img alt="stars" src="https://img.shields.io/github/stars/tardummy01/oscp_scripts-1">
- [drone789/CVE-2012-1823](https://github.com/drone789/CVE-2012-1823)	<img alt="forks" src="https://img.shields.io/github/forks/drone789/CVE-2012-1823">	<img alt="stars" src="https://img.shields.io/github/stars/drone789/CVE-2012-1823">
- [daai1/CVE-2012-1823](https://github.com/daai1/CVE-2012-1823)	<img alt="forks" src="https://img.shields.io/github/forks/daai1/CVE-2012-1823">	<img alt="stars" src="https://img.shields.io/github/stars/daai1/CVE-2012-1823">
- [0xl0k1/CVE-2012-1823](https://github.com/0xl0k1/CVE-2012-1823)	<img alt="forks" src="https://img.shields.io/github/forks/0xl0k1/CVE-2012-1823">	<img alt="stars" src="https://img.shields.io/github/stars/0xl0k1/CVE-2012-1823">

---
## CVE-2012-1705 (2013-01-17T01:55:00)
> Unspecified vulnerability in the Server component in Oracle MySQL 5.1.66 and earlier and 5.5.28 and earlier allows remote authenticated users to affect availability via unknown vectors related to Server Optimizer.
- [Live-Hack-CVE/CVE-2012-1705](https://github.com/Live-Hack-CVE/CVE-2012-1705)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-1705">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-1705">
- [Live-Hack-CVE/CVE-2012-1705](https://github.com/Live-Hack-CVE/CVE-2012-1705)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-1705">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-1705">

---
## CVE-2012-1697 (2012-05-03T22:55:00)
> Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.5.21 and earlier allows remote authenticated users to affect availability via unknown vectors related to Partition.
- [Live-Hack-CVE/CVE-2012-1697](https://github.com/Live-Hack-CVE/CVE-2012-1697)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-1697">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-1697">

---
## CVE-2012-1689 (2012-07-17T22:55:00)
> Unspecified vulnerability in Oracle MySQL Server 5.1.62 and earlier, and 5.5.22 and earlier, allows remote authenticated users to affect availability via unknown vectors related to Server Optimizer.
- [Live-Hack-CVE/CVE-2012-1689](https://github.com/Live-Hack-CVE/CVE-2012-1689)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-1689">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-1689">

---
## CVE-2012-1688 (2012-05-03T22:55:00)
> Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.1.61 and earlier, and 5.5.21 and earlier, allows remote authenticated users to affect availability, related to Server DML.
- [Live-Hack-CVE/CVE-2012-1688](https://github.com/Live-Hack-CVE/CVE-2012-1688)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-1688">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-1688">
- [Live-Hack-CVE/CVE-2012-1688](https://github.com/Live-Hack-CVE/CVE-2012-1688)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-1688">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-1688">

---
## CVE-2012-1495 (2020-01-27T15:15:00)
> install/index.php in WebCalendar before 1.2.5 allows remote attackers to execute arbitrary code via the form_single_user_login parameter.
- [axelbankole/CVE-2012-1495-Webcalendar-](https://github.com/axelbankole/CVE-2012-1495-Webcalendar-)	<img alt="forks" src="https://img.shields.io/github/forks/axelbankole/CVE-2012-1495-Webcalendar-">	<img alt="stars" src="https://img.shields.io/github/stars/axelbankole/CVE-2012-1495-Webcalendar-">

---
## CVE-2012-10006 (2023-01-18T16:15:00)
> A vulnerability classified as critical has been found in ale7714 sigeprosi. This affects an unknown part. The manipulation leads to sql injection. The name of the patch is 5291886f6c992316407c376145d331169c55f25b. It is recommended to apply a patch to fix this issue. The identifier VDB-218493 was assigned to this vulnerability.
- [Live-Hack-CVE/CVE-2012-10006](https://github.com/Live-Hack-CVE/CVE-2012-10006)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-10006">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-10006">

---
## CVE-2012-10005 (2023-01-12T16:15:00)
> A vulnerability has been found in manikandan170890 php-form-builder-class and classified as problematic. Affected by this vulnerability is an unknown functionality of the file PFBC/Element/Textarea.php of the component Textarea Handler. The manipulation of the argument value leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The name of the patch is 74897993818d826595fd5857038e6703456a594a. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-218155.
- [Live-Hack-CVE/CVE-2012-10005](https://github.com/Live-Hack-CVE/CVE-2012-10005)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-10005">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-10005">

---
## CVE-2012-10004 (2023-01-11T07:15:00)
> A vulnerability was found in backdrop-contrib Basic Cart. It has been classified as problematic. Affected is the function basic_cart_checkout_form_submit of the file basic_cart.cart.inc. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 1.x-1.1.1 is able to address this issue. The name of the patch is a10424ccd4b3b4b433cf33b73c1ad608b11890b4. It is recommended to upgrade the affected component. VDB-217950 is the identifier assigned to this vulnerability.
- [Live-Hack-CVE/CVE-2012-10004](https://github.com/Live-Hack-CVE/CVE-2012-10004)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-10004">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-10004">

---
## CVE-2012-10003 (2023-01-03T12:15:00)
> A vulnerability, which was classified as problematic, has been found in ahmyi RivetTracker. This issue affects some unknown processing. The manipulation of the argument $_SERVER['PHP_SELF'] leads to cross site scripting. The attack may be initiated remotely. The name of the patch is f053c5cc2bc44269b0496b5f275e349928a92ef9. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217271.
- [Live-Hack-CVE/CVE-2012-10003](https://github.com/Live-Hack-CVE/CVE-2012-10003)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-10003">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-10003">

---
## CVE-2012-10002 (2023-01-03T09:15:00)
> A vulnerability was found in ahmyi RivetTracker. It has been declared as problematic. Affected by this vulnerability is the function changeColor of the file css.php. The manipulation of the argument set_css leads to cross site scripting. The attack can be launched remotely. The name of the patch is 45a0f33876d58cb7e4a0f17da149e58fc893b858. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217267.
- [Live-Hack-CVE/CVE-2012-10002](https://github.com/Live-Hack-CVE/CVE-2012-10002)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-10002">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-10002">

---
## CVE-2012-0883 (2012-04-18T10:33:00)
> envvars (aka envvars-std) in the Apache HTTP Server before 2.4.2 places a zero-length directory name in the LD_LIBRARY_PATH, which allows local users to gain privileges via a Trojan horse DSO in the current working directory during execution of apachectl.
- [Live-Hack-CVE/CVE-2012-0883](https://github.com/Live-Hack-CVE/CVE-2012-0883)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-0883">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-0883">

---
## CVE-2012-0831 (2012-02-10T20:55:00)
> PHP before 5.3.10 does not properly perform a temporary change to the magic_quotes_gpc directive during the importing of environment variables, which makes it easier for remote attackers to conduct SQL injection attacks via a crafted request, related to main/php_variables.c, sapi/cgi/cgi_main.c, and sapi/fpm/fpm/fpm_main.c.
- [Live-Hack-CVE/CVE-2012-0831](https://github.com/Live-Hack-CVE/CVE-2012-0831)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-0831">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-0831">

---
## CVE-2012-0777 (2012-04-10T23:55:00)
> The JavaScript API in Adobe Reader and Acrobat 9.x before 9.5.1 and 10.x before 10.1.3 on Mac OS X and Linux allows attackers to execute arbitrary code or cause a denial of service (memory corruption) via unspecified vectors.
- [Live-Hack-CVE/CVE-2012-0777](https://github.com/Live-Hack-CVE/CVE-2012-0777)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-0777">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-0777">
- [Live-Hack-CVE/CVE-2012-0777](https://github.com/Live-Hack-CVE/CVE-2012-0777)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-0777">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-0777">

---
## CVE-2012-0578 (2013-01-17T01:55:00)
> Unspecified vulnerability in the Server component in Oracle MySQL 5.5.28 and earlier allows remote authenticated users to affect availability via unknown vectors related to Server Optimizer.
- [Live-Hack-CVE/CVE-2012-0578](https://github.com/Live-Hack-CVE/CVE-2012-0578)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-0578">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-0578">
- [Live-Hack-CVE/CVE-2012-0578](https://github.com/Live-Hack-CVE/CVE-2012-0578)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-0578">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-0578">

---
## CVE-2012-0574 (2013-01-17T01:55:00)
> Unspecified vulnerability in the Server component in Oracle MySQL 5.1.66 and earlier, and 5.5.28 and earlier, allows remote authenticated users to affect availability via unknown vectors.
- [Live-Hack-CVE/CVE-2012-0574](https://github.com/Live-Hack-CVE/CVE-2012-0574)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-0574">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-0574">
- [Live-Hack-CVE/CVE-2012-0574](https://github.com/Live-Hack-CVE/CVE-2012-0574)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-0574">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-0574">

---
## CVE-2012-0572 (2013-01-17T01:55:00)
> Unspecified vulnerability in the Server component in Oracle MySQL 5.1.66 and earlier and 5.5.28 and earlier allows remote authenticated users to affect availability via unknown vectors related to InnoDB.
- [Live-Hack-CVE/CVE-2012-0572](https://github.com/Live-Hack-CVE/CVE-2012-0572)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-0572">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-0572">
- [Live-Hack-CVE/CVE-2012-0572](https://github.com/Live-Hack-CVE/CVE-2012-0572)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-0572">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-0572">

---
## CVE-2012-0540 (2012-07-17T22:55:00)
> Unspecified vulnerability in Oracle MySQL Server 5.1.62 and earlier and 5.5.23 and earlier allows remote authenticated users to affect availability, related to GIS Extension.
- [Live-Hack-CVE/CVE-2012-0540](https://github.com/Live-Hack-CVE/CVE-2012-0540)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-0540">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-0540">
- [Live-Hack-CVE/CVE-2012-0540](https://github.com/Live-Hack-CVE/CVE-2012-0540)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-0540">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-0540">

---
## CVE-2012-0158 (2012-04-10T21:55:00)
> The (1) ListView, (2) ListView2, (3) TreeView, and (4) TreeView2 ActiveX controls in MSCOMCTL.OCX in the Common Controls in Microsoft Office 2003 SP3, 2007 SP2 and SP3, and 2010 Gold and SP1; Office 2003 Web Components SP3; SQL Server 2000 SP4, 2005 SP4, and 2008 SP2, SP3, and R2; BizTalk Server 2002 SP1; Commerce Server 2002 SP4, 2007 SP2, and 2009 Gold and R2; Visual FoxPro 8.0 SP1 and 9.0 SP2; and Visual Basic 6.0 Runtime allow remote attackers to execute arbitrary code via a crafted (a) web site, (b) Office document, or (c) .rtf file that triggers "system state" corruption, as exploited in the wild in April 2012, aka "MSCOMCTL.OCX RCE Vulnerability."
- [Sunqiz/CVE-2012-0158-reproduction](https://github.com/Sunqiz/CVE-2012-0158-reproduction)	<img alt="forks" src="https://img.shields.io/github/forks/Sunqiz/CVE-2012-0158-reproduction">	<img alt="stars" src="https://img.shields.io/github/stars/Sunqiz/CVE-2012-0158-reproduction">
- [RobertoLeonFR-ES/Exploit-Win32.CVE-2012-0158.F.doc](https://github.com/RobertoLeonFR-ES/Exploit-Win32.CVE-2012-0158.F.doc)	<img alt="forks" src="https://img.shields.io/github/forks/RobertoLeonFR-ES/Exploit-Win32.CVE-2012-0158.F.doc">	<img alt="stars" src="https://img.shields.io/github/stars/RobertoLeonFR-ES/Exploit-Win32.CVE-2012-0158.F.doc">

---
## CVE-2012-0053 (2012-01-28T04:05:00)
> protocol.c in the Apache HTTP Server 2.2.x through 2.2.21 does not properly restrict header information during construction of Bad Request (aka 400) error documents, which allows remote attackers to obtain the values of HTTPOnly cookies via vectors involving a (1) long or (2) malformed header in conjunction with crafted web script.
- [Live-Hack-CVE/CVE-2012-0053](https://github.com/Live-Hack-CVE/CVE-2012-0053)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-0053">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-0053">

---
## CVE-2012-0039 (2012-01-14T17:55:00)
> ** DISPUTED ** GLib 2.31.8 and earlier, when the g_str_hash function is used, computes hash values without restricting the ability to trigger hash collisions predictably, which allows context-dependent attackers to cause a denial of service (CPU consumption) via crafted input to an application that maintains a hash table. NOTE: this issue may be disputed by the vendor; the existence of the g_str_hash function is not a vulnerability in the library, because callers of g_hash_table_new and g_hash_table_new_full can specify an arbitrary hash function that is appropriate for the application.
- [Live-Hack-CVE/CVE-2012-0039](https://github.com/Live-Hack-CVE/CVE-2012-0039)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-0039">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-0039">

---
## CVE-2012-0003 (2012-01-10T21:55:00)
> Unspecified vulnerability in winmm.dll in Windows Multimedia Library in Windows Media Player (WMP) in Microsoft Windows XP SP2 and SP3, Server 2003 SP2, Vista SP2, and Server 2008 SP2 allows remote attackers to execute arbitrary code via a crafted MIDI file, aka "MIDI Remote Code Execution Vulnerability."
- [Sunqiz/CVE-2012-0003-reproduction](https://github.com/Sunqiz/CVE-2012-0003-reproduction)	<img alt="forks" src="https://img.shields.io/github/forks/Sunqiz/CVE-2012-0003-reproduction">	<img alt="stars" src="https://img.shields.io/github/stars/Sunqiz/CVE-2012-0003-reproduction">
- [k0keoyo/CVE-2012-0003_eXP](https://github.com/k0keoyo/CVE-2012-0003_eXP)	<img alt="forks" src="https://img.shields.io/github/forks/k0keoyo/CVE-2012-0003_eXP">	<img alt="stars" src="https://img.shields.io/github/stars/k0keoyo/CVE-2012-0003_eXP">
