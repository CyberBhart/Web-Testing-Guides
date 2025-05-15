# **Testing for Weak Encryption**

## **Overview**

Testing for Weak Encryption (WSTG-CRYP-04) involves assessing web applications for cryptographic implementations that use outdated algorithms, short key lengths, predictable keys, or insecure configurations, which can expose sensitive data (e.g., passwords, session tokens, personal information) to decryption or manipulation. According to OWASP, weak encryption mechanisms, such as MD5, DES, or improper key management, fail to adequately protect data, leading to unauthorized access, data breaches, or regulatory non-compliance. This test focuses on identifying encrypted data, analyzing cryptographic algorithms, and verifying their strength in transit (e.g., API payloads, cookies) and at rest (e.g., database fields, configuration files).

**Impact**: Weak encryption can lead to:
- Decryption of sensitive data, exposing user credentials or personal information.
- Forgery of encrypted data, bypassing authentication or authorization.
- Regulatory violations (e.g., GDPR, PCI-DSS) due to inadequate data protection.
- Increased attack surface by enabling brute-force or cryptanalysis attacks.

This guide provides a practical, hands-on methodology for testing weak encryption vulnerabilities, adhering to OWASP’s WSTG-CRYP-04, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing weak encryption mechanisms, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts and analyzes encrypted data in HTTP traffic.
- **Browser Developer Tools**: Inspects client-side scripts for hardcoded keys or weak algorithms.
- **hashcat**: Cracks weak hashes to identify outdated algorithms (e.g., MD5, SHA-1).
- **John the Ripper**: Tests password hashes for weak encryption.
- **Python Cryptography Library**: Analyzes encryption patterns and tests custom cryptographic implementations.

### **Tool Setup Instructions**

1. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
   - Verify: `curl -x http://127.0.0.1:8080 http://example.com`.
2. **Browser Developer Tools**:
   - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
   - No setup required.
3. **hashcat**:
   - Install on Linux: `sudo apt install hashcat`.
   - Install on Windows/Mac: Download from [hashcat.net](https://hashcat.net/hashcat/).
   - Verify: `hashcat --version`.
4. **John the Ripper**:
   - Install on Linux: `sudo apt install john`.
   - Install on Windows/Mac: Download from [openwall.com/john](https://www.openwall.com/john/).
   - Verify: `john --version`.
5. **Python Cryptography Library**:
   - Install Python: `sudo apt install python3`.
   - Install cryptography: `pip install cryptography`.
   - Verify: `python3 -c "import cryptography; print(cryptography.__version__)"`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-CRYP-04, focusing on identifying encrypted data, analyzing cryptographic algorithms, and testing their strength through traffic inspection, client-side analysis, and cryptanalysis.

### **1. Identify Encrypted Data with Burp Suite**

Capture and analyze HTTP traffic to locate encrypted or hashed data and assess its cryptographic strength.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Traffic**:
   - Browse the application, log in, or interact with APIs.
   - Check “HTTP History” for encrypted data (e.g., base64-encoded tokens, hashed passwords) in cookies, parameters, or responses.
3. **Analyze Data**:
   - Identify hash formats (e.g., 32-character MD5, 40-character SHA-1).
   - Look for encrypted data with predictable patterns (e.g., ECB mode repeating blocks).
   - Note endpoints processing these values (e.g., `/api/auth`, `/login`).
4. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Inspect a hashed password:
  ```
  HTTP History -> Select POST /login -> Check for password=5f4dcc3b5aa765d61d8327deb882cf99 -> Send to Repeater -> Note MD5 format
  ```
- **Command 2**: Analyze encrypted token:
  ```
  HTTP History -> Select GET /profile?token=abc123encrypted -> Send to Repeater -> Check token length and encoding
  ```

**Example Vulnerable Request**:
```
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=5f4dcc3b5aa765d61d8327deb882cf99
```

**Remediation**:
- Use bcrypt for password hashing:
  ```python
  from bcrypt import hashpw, gensalt
  hashed = hashpw(password.encode('utf-8'), gensalt())
  ```

### **2. Inspect Client-Side Code with Browser Developer Tools**

Analyze client-side scripts for hardcoded keys, weak algorithms, or insecure encryption practices.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com` and press `F12` in Chrome/Firefox.
2. **Inspect Scripts**:
   - Check “Sources” tab for JavaScript files or inline scripts.
   - Search for cryptographic functions (e.g., `CryptoJS.MD5`, `DES.encrypt`) or hardcoded keys.
3. **Analyze Findings**:
   - Identify weak algorithms (e.g., MD5, DES) or short keys (e.g., `key=secret123`).
   - Check for client-side encryption exposing keys or predictable IVs.
4. **Document Findings**:
   - Save screenshots and script excerpts.

**Browser Developer Tools Commands**:
- **Command 1**: Search for weak algorithms:
  ```
  Sources tab -> Ctrl+F -> Search "MD5" or "DES" -> Inspect script
  ```
- **Command 2**: Find hardcoded keys:
  ```
  Sources tab -> Open main.js -> Ctrl+F -> Search "key =" or "secret" -> Check for constants
  ```

**Example Vulnerable Script**:
```javascript
const key = "secret123";
const encrypted = CryptoJS.DES.encrypt("data", key).toString();
```

**Remediation**:
- Avoid client-side encryption; use server-side encryption:
  ```javascript
  // Server-side Node.js example
  const crypto = require('crypto');
  const key = crypto.randomBytes(32);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  ```

### **3. Crack Weak Hashes with hashcat**

Test password hashes for weak algorithms by attempting to crack them.

**Steps**:
1. **Extract Hashes**:
   - Use Burp Suite to capture hashes (e.g., `password=5f4dcc3b5aa765d61d8327deb882cf99`).
   - Save to a file (e.g., `hashes.txt`).
2. **Run hashcat**:
   - Specify the hash type (e.g., MD5) and use a wordlist or brute-force attack.
   - Check if hashes are cracked quickly, indicating weak algorithms.
3. **Analyze Results**:
   - Cracked hashes confirm weak encryption (e.g., MD5, SHA-1).
   - Expected secure response: Hashes resist cracking (e.g., bcrypt).
4. **Document Findings**:
   - Save hashcat output.

**hashcat Commands**:
- **Command 1**: Crack MD5 hashes with a wordlist:
  ```bash
  hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
  ```
- **Command 2**: Brute-force MD5 hashes:
  ```bash
  hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a
  ```

**Example Vulnerable Output**:
```
5f4dcc3b5aa765d61d8327deb882cf99:password
```

**Remediation**:
- Use Argon2 for password hashing:
  ```python
  from argon2 import PasswordHasher
  ph = PasswordHasher()
  hashed = ph.hash("password")
  ```

### **4. Test Password Hashes with John the Ripper**

Analyze captured password hashes for weak encryption mechanisms.

**Steps**:
1. **Extract Hashes**:
   - Use Burp Suite to capture hashes (e.g., SHA-1: `password=7c4a8d09ca3762af61e59520943dc26494f8941b`).
   - Save to `hashes.txt`.
2. **Run John the Ripper**:
   - Specify the hash format (e.g., SHA-1) and use a wordlist.
   - Test for quick cracking, indicating weak hashing.
3. **Analyze Results**:
   - Cracked hashes indicate weak algorithms or lack of salting.
   - Expected secure response: Hashes resist cracking.
4. **Document Findings**:
   - Save John output.

**John the Ripper Commands**:
- **Command 1**: Crack SHA-1 hashes:
  ```bash
  john --format=Raw-SHA1 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
  ```
- **Command 2**: Test with incremental mode:
  ```bash
  john --format=Raw-SHA1 --incremental hashes.txt
  ```

**Example Vulnerable Output**:
```
password (7c4a8d09ca3762af61e59520943dc26494f8941b)
```

**Remediation**:
- Use salted bcrypt:
  ```php
  $password = "secret123";
  $hashed = password_hash($password, PASSWORD_BCRYPT);
  ```

### **5. Analyze Encryption Patterns with Python Cryptography**

Write scripts to detect weak encryption patterns or test cryptographic implementations.

**Steps**:
1. **Write Python Script**:
   - Create a script to analyze encrypted data for weak algorithms (e.g., ECB mode):
     ```python
     import base64
     from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

     def detect_ecb(ciphertext):
         blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
         return len(blocks) != len(set(blocks))

     # Example: Test a base64-encoded token
     token = "5a8b9c0d5a8b9c0d5a8b9c0d5a8b9c0d"  # Repeating blocks indicate ECB
     ciphertext = base64.b64decode(token)
     if detect_ecb(ciphertext):
         print("Weak encryption detected: Possible ECB mode")
     else:
         print("No ECB mode detected")
     ```
2. **Run Script**:
   - Execute: `python3 detect_ecb.py`.
   - Analyze output for weak encryption indicators.
3. **Verify Findings**:
   - Cross-check with Burp Suite or hashcat.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run ECB detection script:
  ```bash
  python3 detect_ecb.py
  ```
- **Command 2**: Test encrypted data format:
  ```bash
  python3 -c "import base64; print(len(base64.b64decode('5a8b9c0d5a8b9c0d5a8b9c0d5a8b9c0d'))) # Check for block size"
  ```

**Example Vulnerable Output**:
```
Weak encryption detected: Possible ECB mode
```

**Remediation**:
- Use AES-GCM:
  ```python
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  key = AESGCM.generate_key(bit_length=256)
  aesgcm = AESGCM(key)
  ciphertext = aesgcm.encrypt(nonce, data, None)
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-CRYP-04 with practical scenarios based on common weak encryption vulnerabilities observed in penetration testing.

### **Test 1: Weak Password Hashing**

**Objective**: Detect weak hashing algorithms in password submissions.

**Steps**:
1. **Capture Login Request**:
   - Use Burp Suite to intercept `POST /login`.
   - Command:
     ```
     HTTP History -> Select POST /login -> Check for password=5f4dcc3b5aa765d61d8327deb882cf99 -> Note MD5 format
     ```
2. **Crack with hashcat**:
   - Command:
     ```bash
     echo "5f4dcc3b5aa765d61d8327deb882cf99" > hashes.txt
     hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
     ```
3. **Analyze Results**:
   - Quick cracking indicates weak hashing (e.g., MD5).
   - Expected secure response: Uncrackable hash (e.g., bcrypt).
4. **Save Results**:
   - Save Burp Suite and hashcat outputs.

**Example Vulnerable Output**:
```
5f4dcc3b5aa765d61d8327deb882cf99:password
```

**Remediation**:
```python
from bcrypt import hashpw, gensalt
hashed = hashpw(password.encode('utf-8'), gensalt())
```

### **Test 2: Hardcoded Encryption Key**

**Objective**: Identify hardcoded keys in client-side scripts.

**Steps**:
1. **Inspect Scripts**:
   - Use Browser Developer Tools to check JavaScript files.
   - Command:
     ```
     Sources tab -> Open main.js -> Ctrl+F -> Search "key =" -> Check for constants
     ```
2. **Analyze Findings**:
   - Look for keys like `key = "secret123";`.
   - Expected secure response: No keys in client-side code.
3. **Verify with Burp Suite**:
   - Check if encrypted data uses the hardcoded key.
   - Command:
     ```
     HTTP History -> Select POST /api/data -> Check encrypted payload
     ```
4. **Save Results**:
   - Save screenshots and Burp Suite outputs.

**Example Vulnerable Script**:
```javascript
const key = "secret123";
const encrypted = CryptoJS.AES.encrypt("data", key).toString();
```

**Remediation**:
- Use secure key management:
  ```javascript
  // Server-side Node.js example
  const key = require('crypto').randomBytes(32);
  ```

### **Test 3: Weak Encryption in API Payload**

**Objective**: Detect weak encryption algorithms in API data.

**Steps**:
1. **Capture API Request**:
   - Use Burp Suite to find `POST /api/data`.
   - Command:
     ```
     HTTP History -> Select POST /api/data -> Check for encrypted=abc123encrypted -> Send to Repeater
     ```
2. **Analyze with Python**:
   - Command:
     ```bash
     python3 detect_ecb.py
     ```
3. **Analyze Findings**:
   - Check for ECB mode or short key lengths.
   - Expected secure response: Strong encryption (e.g., AES-GCM).
4. **Save Results**:
   - Save Burp Suite and Python outputs.

**Example Vulnerable Output**:
```
Weak encryption detected: Possible ECB mode
```

**Remediation**:
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
ciphertext = AESGCM(key).encrypt(nonce, data, None)
```

### **Test 4: Weak Hash in Database Response**

**Objective**: Detect weak hashing in database-stored data.

**Steps**:
1. **Capture Response**:
   - Use Burp Suite to inspect `GET /api/users`.
   - Command:
     ```
     HTTP History -> Select GET /api/users -> Check for hash=7c4a8d09ca3762af61e59520943dc26494f8941b
     ```
2. **Crack with John the Ripper**:
   - Command:
     ```bash
     echo "7c4a8d09ca3762af61e59520943dc26494f8941b" > hashes.txt
     john --format=Raw-SHA1 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
     ```
3. **Analyze Results**:
   - Cracked hash indicates weak algorithm (e.g., SHA-1).
   - Expected secure response: Strong hashing.
4. **Save Results**:
   - Save Burp Suite and John outputs.

**Example Vulnerable Output**:
```
password (7c4a8d09ca3762af61e59520943dc26494f8941b)
```

**Remediation**:
```php
$hashed = password_hash($password, PASSWORD_ARGON2ID);
```

## **Additional Tips**

- **Inspect All Data**: Check cookies, API payloads, database responses, and client-side code for encrypted or hashed data.
- **Combine Tools**: Use Burp Suite for traffic analysis, hashcat/John for cracking, and Python for pattern detection.
- **Gray-Box Testing**: If source code is available, review cryptographic libraries and key management practices.
- **Document Thoroughly**: Save all commands, outputs, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for cryptanalysis, as cracking hashes or decrypting data may expose sensitive information or violate laws.
- **References**: [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html), [NIST Cryptographic Standards](https://www.nist.gov/cryptography).