# 2006 List

---
## CVE-2006-7204 (2007-05-22T19:30:00)
> The imap_body function in PHP before 4.4.4 does not implement safemode or open_basedir checks, which allows local users to read arbitrary files or list arbitrary directory contents.
- [Live-Hack-CVE/CVE-2006-7204](https://github.com/Live-Hack-CVE/CVE-2006-7204)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2006-7204">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2006-7204">

---
## CVE-2006-3392 (2006-07-06T20:05:00)
> Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML, which allows remote attackers to read arbitrary files, as demonstrated using "..%01" sequences, which bypass the removal of "../" sequences before bytes such as "%01" are removed from the filename.  NOTE: This is a different issue than CVE-2006-3274.
- [kernel-cyber/CVE-2006-3392](https://github.com/kernel-cyber/CVE-2006-3392)	<img alt="forks" src="https://img.shields.io/github/forks/kernel-cyber/CVE-2006-3392">	<img alt="stars" src="https://img.shields.io/github/stars/kernel-cyber/CVE-2006-3392">
- [oxagast/oxasploits](https://github.com/oxagast/oxasploits)	<img alt="forks" src="https://img.shields.io/github/forks/oxagast/oxasploits">	<img alt="stars" src="https://img.shields.io/github/stars/oxagast/oxasploits">
- [gb21oc/ExploitWebmin](https://github.com/gb21oc/ExploitWebmin)	<img alt="forks" src="https://img.shields.io/github/forks/gb21oc/ExploitWebmin">	<img alt="stars" src="https://img.shields.io/github/stars/gb21oc/ExploitWebmin">
- [Adel-kaka-dz/CVE-2006-3392](https://github.com/Adel-kaka-dz/CVE-2006-3392)	<img alt="forks" src="https://img.shields.io/github/forks/Adel-kaka-dz/CVE-2006-3392">	<img alt="stars" src="https://img.shields.io/github/stars/Adel-kaka-dz/CVE-2006-3392">
- [IvanGlinkin/CVE-2006-3392](https://github.com/IvanGlinkin/CVE-2006-3392)	<img alt="forks" src="https://img.shields.io/github/forks/IvanGlinkin/CVE-2006-3392">	<img alt="stars" src="https://img.shields.io/github/stars/IvanGlinkin/CVE-2006-3392">
- [0xtz/CVE-2006-3392](https://github.com/0xtz/CVE-2006-3392)	<img alt="forks" src="https://img.shields.io/github/forks/0xtz/CVE-2006-3392">	<img alt="stars" src="https://img.shields.io/github/stars/0xtz/CVE-2006-3392">
- [g1vi/CVE-2006-3392](https://github.com/g1vi/CVE-2006-3392)	<img alt="forks" src="https://img.shields.io/github/forks/g1vi/CVE-2006-3392">	<img alt="stars" src="https://img.shields.io/github/stars/g1vi/CVE-2006-3392">
- [MrEmpy/CVE-2006-3392](https://github.com/MrEmpy/CVE-2006-3392)	<img alt="forks" src="https://img.shields.io/github/forks/MrEmpy/CVE-2006-3392">	<img alt="stars" src="https://img.shields.io/github/stars/MrEmpy/CVE-2006-3392">

---
## CVE-2006-3360 (2006-07-06T20:05:00)
> Directory traversal vulnerability in index.php in phpSysInfo 2.5.1 allows remote attackers to determine the existence of arbitrary files via a .. (dot dot) sequence and a trailing null (%00) byte in the lng parameter, which will display a different error message if the file exists.
- [Live-Hack-CVE/CVE-2006-3360](https://github.com/Live-Hack-CVE/CVE-2006-3360)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2006-3360">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2006-3360">

---
## CVE-2006-2842 (2006-06-06T20:06:00)
> ** DISPUTED **  PHP remote file inclusion vulnerability in functions/plugin.php in SquirrelMail 1.4.6 and earlier, if register_globals is enabled and magic_quotes_gpc is disabled, allows remote attackers to execute arbitrary PHP code via a URL in the plugins array parameter.  NOTE: this issue has been disputed by third parties, who state that Squirrelmail provides prominent warnings to the administrator when register_globals is enabled.  Since the varieties of administrator negligence are uncountable, perhaps this type of issue should not be included in CVE.  However, the original developer has posted a security advisory, so there might be relevant real-world environments under which this vulnerability is applicable. Successful exploitation requires that "register_globals" is enabled and "magic_quotes_gpc" is disabled.
- [karthi-the-hacker/CVE-2006-2842](https://github.com/karthi-the-hacker/CVE-2006-2842)	<img alt="forks" src="https://img.shields.io/github/forks/karthi-the-hacker/CVE-2006-2842">	<img alt="stars" src="https://img.shields.io/github/stars/karthi-the-hacker/CVE-2006-2842">

---
## CVE-2006-20001 (2023-01-17T20:15:00)
> A carefully crafted If: request header can cause a memory read, or write of a single zero byte, in a pool (heap) memory location beyond the header value sent. This could cause the process to crash. This issue affects Apache HTTP Server 2.4.54 and earlier.
- [Live-Hack-CVE/CVE-2006-20001](https://github.com/Live-Hack-CVE/CVE-2006-20001)	<img alt="forks" src="https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2006-20001">	<img alt="stars" src="https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2006-20001">

---
## CVE-2006-0987 (2006-03-03T11:02:00)
> The default configuration of ISC BIND before 9.4.1-P1, when configured as a caching name server, allows recursive queries and provides additional delegation information to arbitrary IP addresses, which allows remote attackers to cause a denial of service (traffic amplification) via DNS queries with spoofed source IP addresses. This vulnerability affects ISC, BIND versions 9.3.2 and previous.
- [pcastagnaro/check_CVE-2006-0987](https://github.com/pcastagnaro/check_CVE-2006-0987)	<img alt="forks" src="https://img.shields.io/github/forks/pcastagnaro/check_CVE-2006-0987">	<img alt="stars" src="https://img.shields.io/github/stars/pcastagnaro/check_CVE-2006-0987">
