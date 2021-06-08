# Red Team: Summary of Operations

## Table of Contents
- Exposed Services
- Critical Vulnerabilities
- Exploitation

### Exposed Services

Nmap scan results for each machine reveal the below services and OS details:

```bash
$ nmap -sV -O 192.168.1.110
```

![NMap Scan](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Red%20vs%20Blue/nmap_scan.png)

This scan identifies the services below as potential points of entry:
- Target 1
  - 22/tcp open ssh OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
  - 80/tcp open http Apache httpd 2.4.10 ((Debian))
  - 111/tcp open rpcbind 2-4 (RPC #100000)
  - 139/tcp open netbios-ssn Samba smbd 3.X 4.x (workgroup: WORKGROUP)
  - 445/tcp open netbios-ssn Samba smbd 3.X 4.X (workgroup: WORKGROUP)

### Critical Vulnerabilities

The following vulnerabilities were identified on each target:

Command used for vulnerability scan:
```bash
$ nmap -sV --script=vulners -v 192.168.1.110
```

![Vulns Scan](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Red%20vs%20Blue/nmap_vulns.png)

- **Target 1**
  - Port 22:
    - **Vulnerability**: CVE-2001-0554
      - **Description**: Buffer overflow in BSD-based telnetd telnet daemon on various operating systems allows remote attackers to execute arbitrary commands via a set of options including AYT (Are You There), which is not properly handled by the telrcv function.
      - **Severity**: High - 10.0 (CVSS 2.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2015-5600
      - **Description**: The kbdint_next_device function in auth2-chall.c in sshd in OpenSSH through 6.9 does not properly restrict the processing of keyboard-interactive devices within a single connection, which makes it easier for remote attackers to conduct brute-force attacks or cause a denial of service (CPU consumption) via a long and duplicative list in the ssh -oKbdInteractiveDevices option, as demonstrated by a modified client that provides a different password for each pam element on this list.
      - **Severity**: High - 8.5 (CVSS 2.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2020-16088
      - **Description**: iked in OpenIKED, as used in OpenBSD through 6.7, allows authentication bypass because ca.c has the wrong logic for checking whether a public key matches.
      - **Severity**: Critical - 9.8 (CVSS 3.1)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2015-6564
      - **Description**: Use-after-free vulnerability in the mm_answer_pam_free_ctx function in monitor.c in sshd in OpenSSH before 7.0 on non-OpenBSD platforms might allow local users to gain privileges by leveraging control of the sshd uid to send an unexpectedly early MONITOR_REQ_PAM_FREE_CTX request.
      - Severity: Medium - 6.9 (CVSS 2.0)
      - Mitigation: Update to the latest version.

    - **Vulnerability**: CVE-2018-15919
      - **Description**: Remotely observable behaviour in auth-gss2.c in OpenSSH through 7.8 could be used by remote attackers to detect existence of users on a target system when GSS2 is in use. NOTE: the discoverer states 'We understand that the OpenSSH developers do not want to treat such a username enumeration (or "oracle") as a vulnerability.'
      - **Severity**: Medium - 5.3 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2017-15906
      - **Description**: The process_open function in sftp-server.c in OpenSSH before 7.6 does not properly prevent write operations in read only mode, which allows attackers to create zero-length files.
      - **Severity**: Medium - 5.3 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2016-0778
      - **Description**: The (1) roaming_read and (2) roaming_write functions in roaming_common.c in the client in OpenSSH 5.x, 6.x, and 7.x before 7.1p2, when certain proxy and forward options are enabled, do not properly maintain connection file descriptors, which allows remote servers to cause a denial of service (heap-based buffer overflow) or possibly have unspecified other impact by requesting many forwardings.
      - **Severity**: High - 8.1 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2020-14145
      - **Description**: The client side in OpenSSH 5.7 through 8.4 has an Observable Discrepancy leading to an information leak in the algorithm negotiation. This allows man-in-the-middle attackers to target initial connection attempts (where no host key for the server has been cached by the client). NOTE: some reports state that 8.5 and 8.6 are also affected.
      - **Severity**: Medium - 5.9 (CVSS 3.1)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2015-5352
      - **Description**: The x11_open_helper function in channels.c in ssh in OpenSSH before 6.9, when ForwardX11Trusted mode is not used, lacks a check of the refusal deadline for X connections, which makes it easier for remote attackers to bypass intended access restrictions via a connection outside of the permitted time window.
      - **Severity**: Medium - 4.3 (CVSS 2.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2007-2768
      - **Description**: OpenSSH, when using OPIE (One-Time Passwords in Everything) for PAM, allows remote attackers to determine the existence of certain user accounts, which displays a different response if the user account exists and is configured to use one-time passwords (OTP), a similar issue to CVE-2007-2243.
      - **Severity**: Medium - 4.3 (CVSS 2.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2016-0777
      - **Description**: The resend_bytes function in roaming_common.c in the client in OpenSSH 5.x, 6.x, and 7.x before 7.1p2 allows remote servers to obtain sensitive information from process memory by requesting transmission of an entire buffer, as demonstrated by reading a private key.
      - **Severity**:  Medium - 6.5 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2015-6563
      - **Description**: The monitor component in sshd in OpenSSH before 7.0 on non-OpenBSD platforms accepts extraneous username data in MONITOR_REQ_PAM_INIT_CTX requests, which allows local users to conduct impersonation attacks by leveraging any SSH login access in conjunction with control of the sshd uid to send a crafted MONITOR_REQ_PWNAM request, related to monitor.c and monitor_wrap.c.
      - **Severity**: Low - 1.9 (CVSS 2.0)
      - **Mitigation**: Update to the latest version.

  - Port 80:
    - **Vulnerability**: CVE-2017-7679
      - **Description**: In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, mod_mime can read one byte past the end of a buffer when sending a malicious Content-Type response header.
      - **Severity**: Critical - 9.8 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2017-7668
      - **Description**: The HTTP strict parsing changes added in Apache httpd 2.2.32 and 2.4.24 introduced a bug in token list parsing, which allows ap_find_token() to search past the end of its input string. By maliciously crafting a sequence of request headers, an attacker may be able to cause a segmentation fault, or to force ap_find_token() to return an incorrect value.
      - **Severity**:  Critical - 9.8 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2017-3169
      - **Description**: In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, mod_ssl may dereference a NULL pointer when third-party modules call ap_hook_process_connection() during an HTTP request to an HTTPS port.
      - **Severity**: Critical - 9.8 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2017-3167
      - D**escription**: In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, use of the ap_get_basic_auth_pw() by third-party modules outside of the authentication phase may lead to authentication requirements being bypassed.
      - **Severity**: Critical - 9.8 (CVSS 3.1) 
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2018-1312
      - **Description**: In Apache httpd 2.2.0 to 2.4.29, when generating an HTTP Digest authentication challenge, the nonce sent to prevent reply attacks was not correctly generated using a pseudo-random seed. In a cluster of servers using a common Digest authentication configuration, HTTP requests could be replayed across servers by an attacker without detection.
      - **Severity**: Critical - 9.8 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2017-15715
      - **Description**: In Apache httpd 2.4.0 to 2.4.29, the expression specified in <FilesMatch> could match '$' to a newline character in a malicious filename, rather than matching only the end of the filename. This could be exploited in environments where uploads of some files are externally blocked, but only by matching the trailing portion of the filename.
      - **Severity**: High - 8.1 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.
      
    - **Vulnerability**: CVE-2017-9788
      - **Description**: In Apache httpd before 2.2.34 and 2.4.x before 2.4.27, the value placeholder in [Proxy-]Authorization headers of type 'Digest' was not initialized or reset before or between successive key=value assignments by mod_auth_digest. Providing an initial key with no '=' assignment could reflect the stale value of uninitialized pool memory used by the prior request, leading to leakage of potentially confidential information, and a segfault in other cases resulting in denial of service.
      - **Severity**: Critical - 9.1 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2019-0217
      - **Description**: In Apache HTTP Server 2.4 release 2.4.38 and prior, a race condition in mod_auth_digest when running in a threaded server could allow a user with valid credentials to authenticate using another username, bypassing configured access control restrictions.
      - **Severity**: High - 7.5 (CVSS 3.1)
      - **Mitigation**: Update to the latest version.
      
    - **Vulnerability**: CVE-2020-1927
      - **Description**: In Apache HTTP Server 2.4.0 to 2.4.41, redirects configured with mod_rewrite that were intended to be self-referential might be fooled by encoded newlines and redirect instead to an an unexpected URL within the request URL.
      - **Severity**: Medium - 6.1 (CVSS 3.1)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2019-10098
      - **Description**: In Apache HTTP server 2.4.0 to 2.4.39, Redirects configured with mod_rewrite that were intended to be self-referential might be fooled by encoded newlines and redirect instead to an unexpected URL within the request URL.
      - **Severity**: Medium - 6.1 (CVSS 3.1) 
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2016-5387
      - **Description**: The Apache HTTP Server through 2.4.23 follows RFC 3875 section 4.1.18 and therefore does not protect applications from the presence of untrusted client data in the HTTP_PROXY environment variable, which might allow remote attackers to redirect an application's outbound HTTP traffic to an arbitrary proxy server via a crafted Proxy header in an HTTP request, aka an "httpoxy" issue. NOTE: the vendor states "This mitigation has been assigned the identifier CVE-2016-5387"; in other words, this is not a CVE ID for a vulnerability.
      - **Severity**: High - 8.1 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.
      
    - **Vulnerability**: CVE-2020-1934
      - **Description**: In Apache HTTP Server 2.4.0 to 2.4.41, mod_proxy_ftp may use uninitialized memory when proxying to a malicious FTP server.
      - **Severity**: Medium - 5.3 (CVSS 3.x)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2019-0220
      - **Description**: A vulnerability was found in Apache HTTP Server 2.4.0 to 2.4.38. When the path component of a request URL - contains multiple consecutive slashes ('/'), directives such as LocationMatch and RewriteRule must account for duplicates in regular expressions while other aspects of the servers processing will implicitly collapse them.
      - **Severity**: Medium - 5.3 (CVSS 3.1)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2018-17199
      - **Description**: In Apache HTTP Server 2.4 release 2.4.37 and prior, mod_session checks the session expiry time before decoding the session. This causes session expiry time to be ignored for mod_session_cookie sessions since the expiry time is loaded when the session is decoded.
      - **Severity**: High - 7.5 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2018-17189
      - **Description**: In Apache HTTP server versions 2.4.37 and prior, by sending request bodies in a slow loris way to plain resources, the h2 stream for that request unnecessarily occupied a server thread cleaning up that incoming data. This affects only HTTP/2 (mod_http2) connections.
      - **Severity**: Medium - 5.3 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.
      
    - **Vulnerability**: CVE-2018-1303
      - **Description**: A specially crafted HTTP request header could have crashed the Apache HTTP Server prior to version 2.4.30 due to an out of bound read while preparing data to be cached in shared memory. It could be used as a Denial of Service attack against users of mod_cache_socache. The vulnerability is considered as low risk since mod_cache_socache is not widely used, mod_cache_disk is not concerned by this vulnerability. 
      - **Severity**:** High - 7.5 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2017-9798
      - **Description**: Apache httpd allows remote attackers to read secret data from process memory if the Limit directive can be set in a user's .htaccess file, or if httpd.conf has certain misconfigurations, aka Optionsbleed. This affects the Apache HTTP Server through 2.2.34 and 2.4.x through 2.4.27. The attacker sends an unauthenticated OPTIONS HTTP request when attempting to read secret data. This is a use-after-free issue and thus secret data is not always sent, and the specific data depends on many factors including configuration. Exploitation with .htaccess can be blocked with a patch to the ap_limit_section function in server/core.c.
      - **Severity**: High - 7.5 (CVSS 3.1)
      - **Mitigation: Update to the latest version.

    - **Vulnerability**: CVE-2017-15710
      - **Description**: In Apache httpd 2.0.23 to 2.0.65, 2.2.0 to 2.2.34, and 2.4.0 to 2.4.29, mod_authnz_ldap, if configured with AuthLDAPCharsetConfig, uses the Accept-Language header value to lookup the right charset encoding when verifying the user's credentials. If the header value is not present in the charset conversion table, a fallback mechanism is used to truncate it to a two characters value to allow a quick retry (for example, 'en-US' is truncated to 'en'). A header value of less than two characters forces an out of bound write of one NUL byte to a memory location that is not part of the string. In the worst case, quite unlikely, the process would crash which could be used as a Denial of Service attack. In the more likely case, this memory is already reserved for future use and the issue has no effect at all.
      - **Severity**: High - 7.5 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2016-8743
      - **Description**: Apache HTTP Server, in all releases prior to 2.2.32 and 2.4.25, was liberal in the whitespace accepted from requests and sent in response lines and headers. Accepting these different behaviors represented a security concern when httpd participates in any chain of proxies or interacts with back-end application servers, either through mod_proxy or using conventional CGI mechanisms, and may result in request smuggling, response splitting and cache pollution.
      - **Severity**: High - 7.5 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2016-2161
      - **Description**: In Apache HTTP Server versions 2.4.0 to 2.4.23, malicious input to mod_auth_digest can cause the server to crash, and each instance continues to crash even for subsequently valid requests.
      - **Severity**: High - 7.5 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.

    -  **Vulnerability**: CVE-2016-0736
        - **Description**: In Apache HTTP Server versions 2.4.0 to 2.4.23, mod_session_crypto was encrypting its data/cookie using the configured ciphers with possibly either CBC or ECB modes of operation (AES256-CBC by default), hence no selectable or built in authenticated encryption. This made it vulnerable to padding oracle attacks, particularly with CBC.
        - **Severity**: High - 7.5(CVSS 3.0)
        - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2015-3183
      - **Description**: The chunked transfer coding implementation in the Apache HTTP Server before 2.4.14 does not properly parse chunk headers, which allows remote attackers to conduct HTTP request smuggling attacks via a crafted request, related to mishandling of large chunk-size values and invalid chunk-extension characters in modules/http/http_filters.c.
      - **Severity**: Medium - 5.0 (CVSS 2.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2015-0228
      - **Description**: The lua_websocket_read function in lua_request.c in the mod_lua module in the Apache HTTP Server through 2.4.12 allows remote attackers to cause a denial of service (child-process crash) by sending a crafted WebSocket Ping frame after a Lua script has called the wsupgrade function.
      - **Severity**: Medium - 5.0 (CVSS 2.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2014-3583
      - **Description**: The handle_headers function in mod_proxy_fcgi.c in the mod_proxy_fcgi module in the Apache HTTP Server 2.4.10 allows remote FastCGI servers to cause a denial of service (buffer over-read and daemon crash) via long response headers.
      - **Severity**: Medium - 5.0 (CVSS 2.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2019-10092
      - **Description**: In Apache HTTP Server 2.4.0-2.4.39, a limited cross-site scripting issue was reported affecting the mod_proxy error page. An attacker could cause the link on the error page to be malformed and instead point to a page of their choice. This would only be exploitable where a server was set up with proxying enabled but was misconfigured in such a way that the Proxy Error page was displayed.
      - **Severity**: Medium - 6.1 (CVSS 3.1)
      - **Mitigation*: Update to the latest version.
      
    - **Vulnerability**: CVE-2020-11985
      - **Description**: IP address spoofing when proxying using mod_remoteip and mod_rewrite For configurations using proxying with mod_remoteip and certain mod_rewrite rules, an attacker could spoof their IP address for logging and PHP scripts. Note this issue was fixed in Apache HTTP Server 2.4.24 but was retrospectively allocated a low severity CVE in 2020.
      - **Severity**: Medium - 5.3 (CVSS 3.1)
      - **Mitigation**: Update to the latest version. 

    - **Vulnerability**: CVE-2018-1302
      - **Description**: When an HTTP/2 stream was destroyed after being handled, the Apache HTTP Server prior to version 2.4.30 could have written a NULL pointer potentially to an already freed memory. The memory pools maintained by the server make this vulnerability hard to trigger in usual configurations, the reporter and the team could not reproduce it outside debug builds, so it is classified as low risk.
      - **Severity**: Medium - 5.9 (CVSS 3.0)
      - **Mitigation*: Update to the latest version.

    - **Vulnerability**: CVE-2018-1301
      - **Description**: A specially crafted request could have crashed the Apache HTTP Server prior to version 2.4.30, due to an out of bound access after a size limit is reached by reading the HTTP header. This vulnerability is considered very hard if not impossible to trigger in non-debug mode (both log and build level), so it is classified as low risk for common server usage.
      - **Severity**: Medium - 5.9 (CVSS 3.0)
      - **Mitigation**: Update to the latest version. 

    - **Vulnerability**: CVE-2016-4975
      - **Description**: Possible CRLF injection allowing HTTP response splitting attacks for sites which use mod_userdir. This issue was mitigated by changes made in 2.4.25 and 2.2.32 which prohibit CR or LF injection into the "Location" or other outbound header key or value. Fixed in Apache HTTP Server 2.4.25 (Affected 2.4.1-2.4.23). Fixed in Apache HTTP Server 2.2.32 (Affected 2.2.0-2.2.31).
      - **Severity**: Medium - 6.1 (CVSS 3.0)
      - **Mitigation**: Update to the latest version. 

    - **Vulnerability**: CVE-2015-3185
      - **Description**: The ap_some_auth_required function in server/request.c in the Apache HTTP Server 2.4.x before 2.4.14 does not consider that a Require directive may be associated with an authorization setting rather than an authentication setting, which allows remote attackers to bypass intended access restrictions in opportunistic circumstances by leveraging the presence of a module that relies on the 2.2 API behavior.
      - **Severity**: Medium - 4.3 (CVSS 2.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2014-8109
      - **Description**: mod_lua.c in the mod_lua module in the Apache HTTP Server 2.3.x and 2.4.x through 2.4.10 does not support an httpd configuration in which the same Lua authorization provider is used with different arguments within different contexts, which allows remote attackers to bypass intended access restrictions in opportunistic circumstances by leveraging multiple Require directives, as demonstrated by a configuration that specifies authorization for one group to access a certain directory, and authorization for a second group to access a second directory.
      - **Severity**: Medium - 4.3 (CVSS 2.0)
      - **Mitigation**: Update to the latest version.

    - **Vulnerability**: CVE-2018-1283
      - **Description**: In Apache httpd 2.4.0 to 2.4.29, when mod_session is configured to forward its session data to CGI applications (SessionEnv on, not the default), a remote user may influence their content by using a "Session" header. This comes from the "HTTP_SESSION" variable name used by mod_session to forward its data to CGIs, since the prefix "HTTP_" is also used by the Apache HTTP Server to pass HTTP header fields, per CGI specifications.
      - **Severity**: Medium - 5.3 (CVSS 3.0)
      - **Mitigation**: Update to the latest version. 

    - **Vulnerability**: CVE-2016-8612
      - **Description**: Apache HTTP Server mod_cluster before version httpd 2.4.23 is vulnerable to an Improper Input Validation in the protocol parsing logic in the load balancer resulting in a Segmentation Fault in the serving httpd process.
      - **Severity**: Medium - 4.3 (CVSS 3.0)
      - **Mitigation**: Update to the latest version.


### Exploitation

The Red Team was able to penetrate `Target 1` and retrieve the following confidential data:
- Target 1
  - `flag1.txt`: b9bbcb33e11b8@be759c4e844862482d
    - **Exploit Used**
      - Inspected source code of service.html within open browser 
        - http://192.168.1.110/service.html

![flag 1](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Red%20vs%20Blue/flag1.png)

  - `flag2.txt`: fc3fd58dcdad9ab23faca6e9a36e581c
  - `flag3.txt`: fafcolab56659591e7dccf93122776cd2
    - **Exploit Used**
      - WPScan exposed user names indicating a weak security policy
        ```bash
        $ wpscan --url http://192.168.1.110/wordpress --enumerate u
        ```
      - Hydra exploited a weak password policy
        ```bash
        $ hydra -l michael -P /usr/share/wordlist/rockyou.txt 192.168.1.110 -t 4 ssh
        ```

![flag 2](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Red%20vs%20Blue/flag2_cmd.png)
![flag 3 command](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Red%20vs%20Blue/flag3_cmd.png)
![flag 3](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Red%20vs%20Blue/flag3.png)

  - `flag4.txt`: 715dea6c055b9fe3337544932f2941ce
    - **Exploit Used**
      - Sudo privleges to run Python allowed root access through Python shell exploit
        ```bash
        $ sudo python -c 'import pty; pty.spawn("/bin/bash")'
        ```

![flag 4](https://github.com/thejohnkelly/FinalProjectReport/blob/main/screen_grabs/Red%20vs%20Blue/flag4_file.png)
