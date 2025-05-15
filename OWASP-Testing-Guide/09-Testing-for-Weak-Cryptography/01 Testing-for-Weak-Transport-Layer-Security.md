# **Testing for Weak Transport Layer Security**

## **Overview**

Testing for Weak Transport Layer Security (TLS) (WSTG-CRYP-01) involves assessing the security of a web application’s TLS/SSL configuration to ensure data transmitted between clients and servers is protected against interception, decryption, or manipulation. According to OWASP, weak TLS configurations—such as outdated protocols (e.g., SSLv3, TLS 1.0), weak cipher suites (e.g., RC4, DES), or misconfigured certificates—can expose sensitive data (e.g., credentials, session tokens) to man-in-the-middle (MITM) attacks, session hijacking, or data breaches. This test evaluates protocol versions, cipher suites, certificate validity, security headers, and related configurations to identify vulnerabilities.

**Impact**: Weak TLS configurations can lead to:
- Interception of sensitive data via MITM attacks.
- Exposure of user credentials or session tokens due to decryptable traffic.
- Loss of trust from invalid or expired certificates.
- Exploitation of misconfigurations (e.g., CRIME, insecure redirects) for data manipulation.

This guide provides a practical, hands-on methodology for testing weak TLS configurations, adhering to OWASP’s WSTG-CRYP-01, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing weak TLS configurations, with at least two specific commands or configurations per tool for real security testing:

- **sslscan**: Enumerates supported TLS protocols and cipher suites.
- **testssl.sh**: Comprehensive script for testing TLS/SSL configurations.
- **OpenSSL**: Analyzes certificates and tests protocol support.
- **Nmap**: Scans for TLS protocol and cipher details.
- **Browser Developer Tools**: Inspects certificates, security headers, and mixed content.

### **Tool Setup Instructions**

1. **sslscan**:
   - Install on Linux: `sudo apt install sslscan`.
   - Install on Windows/Mac: Download from [GitHub](https://github.com/rbsec/sslscan).
   - Verify: `sslscan --version`.
2. **testssl.sh**:
   - Download from [testssl.sh](https://testssl.sh/).
   - Extract and run: `chmod +x testssl.sh`.
   - Verify: `./testssl.sh --version`.
3. **OpenSSL**:
   - Install on Linux: `sudo apt install openssl`.
   - Install on Windows/Mac: Pre-installed or download from [openssl.org](https://www.openssl.org/).
   - Verify: `openssl version`.
4. **Nmap**:
   - Install on Linux: `sudo apt install nmap`.
   - Install on Windows/Mac: Download from [nmap.org](https://nmap.org/).
   - Verify: `nmap --version`.
5. **Browser Developer Tools**:
   - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
   - No setup required.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-CRYP-01, focusing on analyzing TLS protocols, cipher suites, certificates, and related configurations to identify weaknesses.

### **1. Enumerate TLS Protocols and Ciphers with sslscan**

Identify supported TLS/SSL protocols and cipher suites to detect outdated or weak configurations.

**Steps**:
1. **Run sslscan**:
   - Scan the target domain to list protocols and ciphers.
   - Check for deprecated protocols (e.g., SSLv2, SSLv3, TLS 1.0, TLS 1.1) and weak ciphers (e.g., RC4, DES).
2. **Analyze Output**:
   - Verify that only secure protocols (TLS 1.2, TLS 1.3) and strong ciphers (e.g., AES-GCM, CHACHA20) are supported.
   - Note any weak or anonymous ciphers (e.g., NULL, EXPORT).
3. **Document Findings**:
   - Save scan output to a file.

**sslscan Commands**:
- **Command 1**: Scan for all protocols and ciphers:
  ```bash
  sslscan example.com > sslscan_results.txt
  ```
- **Command 2**: Check for specific protocol support:
  ```bash
  sslscan --tlsall example.com
  ```

**Example Vulnerable Output**:
```
Testing SSL server example.com on port 443
  Supported Server Cipher(s):
    Accepted  SSLv3  RC4-MD5
    Accepted  TLSv1.0  DES-CBC-SHA
```

**Remediation**:
- Disable weak protocols and ciphers:
  ```apache
  SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
  SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!DES
  ```

### **2. Comprehensive TLS Testing with testssl.sh**

Perform an in-depth analysis of TLS configurations, including protocols, ciphers, and vulnerabilities.

**Steps**:
1. **Run testssl.sh**:
   - Scan the target domain for protocol support, cipher strength, and known vulnerabilities (e.g., Heartbleed, CRIME).
   - Use verbose mode for detailed output.
2. **Analyze Output**:
   - Check for deprecated protocols, weak ciphers, or compression (e.g., TLS compression enabling CRIME).
   - Verify certificate details and HSTS enforcement.
3. **Document Findings**:
   - Save HTML or text output.

**testssl.sh Commands**:
- **Command 1**: Run a full TLS scan:
  ```bash
  ./testssl.sh --full example.com > testssl_results.html
  ```
- **Command 2**: Test for specific vulnerabilities:
  ```bash
  ./testssl.sh --vulnerable example.com
  ```

**Example Vulnerable Output**:
```
SSLv3: enabled (WEAK)
Cipher: RC4-SHA (WEAK)
Compression: enabled (CRIME vulnerable)
```

**Remediation**:
- Disable compression and weak protocols:
  ```nginx
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
  ssl_prefer_server_ciphers on;
  ssl_comp off;
  ```

### **3. Analyze Certificates with OpenSSL**

Verify certificate validity, trust, and configuration.

**Steps**:
1. **Connect to Server**:
   - Use OpenSSL to retrieve the server’s certificate.
   - Check for expiration, hostname mismatch, or untrusted issuers.
2. **Test Protocol Support**:
   - Attempt connections with deprecated protocols (e.g., SSLv3).
3. **Analyze Output**:
   - Verify certificate details (e.g., CN, SAN, validity period).
   - Check for self-signed or expired certificates.
4. **Document Findings**:
   - Save certificate details.

**OpenSSL Commands**:
- **Command 1**: Retrieve and inspect certificate:
  ```bash
  openssl s_client -connect example.com:443 -servername example.com < /dev/null | openssl x509 -text -noout
  ```
- **Command 2**: Test for SSLv3 support:
  ```bash
  openssl s_client -connect example.com:443 -ssl3
  ```

**Example Vulnerable Output**:
```
Certificate:
  Subject: CN=wrong.example.com
  Not After: Jan 01 2024 (expired)
connect: SSLv3 handshake successful
```

**Remediation**:
- Use valid certificates:
  ```bash
  # Generate CSR and obtain certificate from a trusted CA
  openssl req -new -key server.key -out server.csr
  ```

### **4. Scan TLS Configurations with Nmap**

Use Nmap scripts to enumerate TLS protocols and ciphers.

**Steps**:
1. **Run Nmap Scan**:
   - Use the `ssl-enum-ciphers` script to list supported protocols and ciphers.
   - Check for weak or deprecated configurations.
2. **Analyze Output**:
   - Identify SSLv3, TLS 1.0, or weak ciphers (e.g., RC4).
   - Note certificate issues or misconfigurations.
3. **Document Findings**:
   - Save scan output.

**Nmap Commands**:
- **Command 1**: Enumerate TLS ciphers:
  ```bash
  nmap --script ssl-enum-ciphers -p 443 example.com > nmap_tls_results.txt
  ```
- **Command 2**: Check certificate details:
  ```bash
  nmap --script ssl-cert -p 443 example.com
  ```

**Example Vulnerable Output**:
```
443/tcp open  https
| ssl-enum-ciphers:
|   SSLv3:
|     ciphers:
|       DES-CBC-SHA (weak)
```

**Remediation**:
- Restrict protocols in server configuration:
  ```apache
  SSLProtocol TLSv1.2 TLSv1.3
  ```

### **5. Inspect Security Headers and Content with Browser Developer Tools**

Verify HSTS, secure cookies, and mixed content issues.

**Steps**:
1. **Open Browser Developer Tools**:
   - Access `F12` in Chrome/Firefox on `https://example.com`.
2. **Check Security Headers**:
   - Inspect `Network` tab for `Strict-Transport-Security` header.
   - Verify cookie attributes (e.g., Secure, HttpOnly).
3. **Test for Mixed Content**:
   - Load the page and check for HTTP resources (e.g., images, scripts).
4. **Analyze Certificate**:
   - View certificate details in the `Security` tab.
5. **Document Findings**:
   - Save screenshots and network logs.

**Browser Developer Tools Commands**:
- **Command 1**: Check HSTS header:
  ```
  Network tab -> Select GET https://example.com -> Headers -> Response Headers -> Look for Strict-Transport-Security
  ```
- **Command 2**: Inspect certificate:
  ```
  Security tab -> View Certificate -> Check Subject, Validity, and Issuer
  ```

**Example Vulnerable Finding**:
- Missing `Strict-Transport-Security` header.
- Certificate expired or hostname mismatch.

**Remediation**:
- Enable HSTS:
  ```apache
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  ```
- Set secure cookies:
  ```php
  setcookie('session', 'abc123', ['secure' => true, 'httponly' => true]);
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-CRYP-01 with practical scenarios based on common TLS vulnerabilities observed in penetration testing.

### **Test 1: Deprecated Protocol Support**

**Objective**: Check for support of outdated protocols (e.g., SSLv3, TLS 1.0).

**Steps**:
1. **Run sslscan**:
   - Command:
     ```bash
     sslscan --no-colour example.com > sslscan_deprecated.txt
     ```
2. **Analyze Output**:
   - Look for SSLv3, TLS 1.0, or TLS 1.1.
   - Expected secure response: Only TLS 1.2/TLS 1.3 supported.
3. **Verify with OpenSSL**:
   - Command:
     ```bash
     openssl s_client -connect example.com:443 -tls1
     ```
4. **Save Results**:
   - Save scan outputs.

**Example Vulnerable Output**:
```
Accepted  TLSv1.0  AES128-SHA
```

**Remediation**:
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
```

### **Test 2: Weak Cipher Suites**

**Objective**: Identify weak or deprecated cipher suites.

**Steps**:
1. **Run testssl.sh**:
   - Command:
     ```bash
     ./testssl.sh --ciphers example.com > testssl_ciphers.txt
     ```
2. **Analyze Output**:
   - Check for RC4, DES, or NULL ciphers.
   - Expected secure response: Only strong ciphers (e.g., AES-GCM).
3. **Verify with Nmap**:
   - Command:
     ```bash
     nmap --script ssl-enum-ciphers -p 443 example.com
     ```
4. **Save Results**:
   - Save scan outputs.

**Example Vulnerable Output**:
```
Cipher: RC4-MD5 (WEAK)
```

**Remediation**:
```apache
SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256
```

### **Test 3: Invalid Certificate**

**Objective**: Verify certificate validity and trust.

**Steps**:
1. **Use OpenSSL**:
   - Command:
     ```bash
     openssl s_client -connect example.com:443 -servername example.com < /dev/null | openssl x509 -text -noout
     ```
2. **Analyze Output**:
   - Check for expired dates, hostname mismatches, or self-signed certificates.
   - Expected secure response: Valid, trusted certificate.
3. **Verify in Browser**:
   - Command:
     ```
     Security tab -> View Certificate -> Check Validity and CN
     ```
4. **Save Results**:
   - Save certificate details.

**Example Vulnerable Output**:
```
Not After: Dec 31 2024 (expired)
Subject: CN=wrong.example.com
```

**Remediation**:
- Obtain a valid certificate from a trusted CA:
  ```bash
  certbot certonly --apache -d example.com
  ```

### **Test 4: Missing HSTS and Insecure Cookies**

**Objective**: Check for HSTS enforcement and secure cookie flags.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and open `F12`.
2. **Check Headers**:
   - Command:
     ```
     Network tab -> Select GET https://example.com -> Headers -> Look for Strict-Transport-Security
     ```
3. **Inspect Cookies**:
   - Command:
     ```
     Application tab -> Cookies -> Check for Secure and HttpOnly flags
     ```
4. **Analyze Findings**:
   - Verify HSTS presence and secure cookie attributes.
   - Expected secure response: HSTS enabled, cookies marked Secure.
5. **Save Results**:
   - Save screenshots.

**Example Vulnerable Finding**:
- No `Strict-Transport-Security` header.
- Cookie: `session=abc123; path=/` (missing Secure flag).

**Remediation**:
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

## **Additional Tips**

- **Test All Endpoints**: Scan all domains, subdomains, and ports (e.g., 443, 8443) for TLS configurations.
- **Combine Tools**: Use sslscan for quick scans, testssl.sh for comprehensive analysis, and OpenSSL for certificate details.
- **Gray-Box Testing**: If documentation is available, check server configurations or certificate policies.
- **Document Thoroughly**: Save all scan outputs, screenshots, and findings in a report.
- **Ethical Considerations**: Avoid disruptive scans (e.g., excessive requests) on live systems without explicit permission.
- **References**: [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html), [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/).