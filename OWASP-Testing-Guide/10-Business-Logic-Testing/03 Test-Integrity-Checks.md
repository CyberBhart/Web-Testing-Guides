# **Test Integrity Checks**

## **Overview**

Testing integrity checks (WSTG-BUSL-03) involves assessing whether a web application enforces mechanisms to prevent unauthorized tampering with critical data, such as transaction details, user inputs, or session parameters. According to OWASP, integrity checks, such as Hash-based Message Authentication Codes (HMACs), digital signatures, or checksums, ensure that data remains unaltered during transmission or processing. Weak or absent integrity checks allow attackers to modify data (e.g., prices, quantities, or user roles) to bypass business logic, leading to unauthorized actions or data corruption. This test focuses on identifying vulnerabilities where attackers can tamper with data without detection.

**Impact**: Weak integrity checks can lead to:
- Unauthorized modifications (e.g., altering order amounts in e-commerce).
- Bypassing business logic (e.g., changing user permissions).
- Data integrity violations (e.g., tampering with account balances).
- Financial loss or reputational damage due to exploited logic flaws.

This guide provides a step-by-step methodology for testing integrity checks, adhering to OWASP’s WSTG-BUSL-03, with practical tools, real-world test cases, and remediation strategies for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing integrity checks, suitable for both novice and experienced testers:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to test data tampering.
- **OWASP ZAP**: Open-source web proxy for analyzing and modifying requests.
- **cURL**: Command-line tool for crafting and sending tampered HTTP requests.
- **Postman**: Tool for testing API endpoints and manipulating parameters.
- **Browser Developer Tools**: Built-in browser tools (Chrome/Firefox) for inspecting and modifying form data.
- **FoxyProxy**: Browser extension to route traffic through Burp Suite or OWASP ZAP.
- **Tamper Data**: Browser extension for intercepting and modifying requests (Firefox).
- **Charles Proxy**: Proxy tool for analyzing and modifying mobile or web traffic.
- **Python Requests Library**: Python library for scripting tampered HTTP requests.
- **HashCalc**: Tool for generating and verifying hashes to test integrity mechanisms.

### **Tool Setup Instructions**

1. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
2. **OWASP ZAP**:
   - Download from [owasp.org](https://www.zaproxy.org/download/).
   - Run: `./zap.sh` (Linux) or `zap.bat` (Windows).
   - Configure proxy: 127.0.0.1:8080.
3. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
4. **Postman**:
   - Download from [postman.com](https://www.postman.com/downloads/).
   - Install and create a free account.
   - Verify: Open Postman and check version.
5. **Browser Developer Tools**:
   - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
   - No setup required.
6. **FoxyProxy**:
   - Install as a browser extension (Chrome/Firefox).
   - Configure to route traffic through Burp Suite or OWASP ZAP (127.0.0.1:8080).
7. **Tamper Data**:
   - Install on Firefox from add-ons store.
   - Enable and verify request interception.
8. **Charles Proxy**:
   - Download from [charlesproxy.com](https://www.charlesproxy.com/).
   - Configure proxy: 127.0.0.1:8888.
   - Verify: Start proxy and check traffic.
9. **Python Requests Library**:
   - Install Python: `sudo apt install python3`.
   - Install Requests: `pip install requests`.
   - Verify: `python3 -c "import requests; print(requests.__version__)"`.
10. **HashCalc**:
    - Download from [slavasoft.com/hashcalc/](https://slavasoft.com/hashcalc/) (Windows) or use `sha256sum` on Linux.
    - Verify: Run `hashcalc.exe` or `sha256sum --version`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-BUSL-03, focusing on tampering with data and observing whether the application detects and rejects unauthorized modifications.

### **1. Identify Critical Data Points with Burp Suite**

Map requests containing critical data that should be protected by integrity checks.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Interact with the Application**:
   - Perform actions like submitting forms, updating profiles, or placing orders.
   - Capture requests in Burp Suite’s “HTTP History”.
3. **Identify Critical Data**:
   - Look for parameters like `price`, `quantity`, `user_id`, or `total` in requests (e.g., `POST /order/submit`).
   - Note any integrity mechanisms (e.g., `hash`, `signature`, or `checksum` fields).
4. **Document Findings**:
   - Save request details (e.g., URLs, parameters, integrity fields) in Burp Suite’s “Logger”.

**Example Request**:
```
POST /order/submit HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

item_id=123&quantity=2&price=99.99&hash=5f4dcc3b5aa765d61d8327deb882cf99
```

**Remediation**:
- Implement HMACs for data integrity:
  ```php
  $secret = 'your-secret-key';
  $data = $_POST['item_id'] . $_POST['quantity'] . $_POST['price'];
  $hash = hash_hmac('sha256', $data, $secret);
  if ($_POST['hash'] !== $hash) {
      die('Data tampered');
  }
  ```

### **2. Tamper with Data Using Burp Suite Repeater**

Modify critical data and test whether the application detects tampering.

**Steps**:
1. **Send to Repeater**:
   - Right-click a request in “HTTP History” and select “Send to Repeater”.
   - Modify parameters (e.g., change `price=99.99` to `price=0.01` without updating `hash`).
   - Send the tampered request.
2. **Test Edge Cases**:
   - Alter values (e.g., `quantity=999999`, `user_id=admin`).
   - Remove or corrupt integrity fields (e.g., delete `hash`, set `signature=invalid`).
   - Replay requests with outdated or incorrect hashes.
3. **Analyze Response**:
   - Check if the application rejects tampered data (e.g., returns error).
   - Look for acceptance of invalid data or verbose error messages.
4. **Document Findings**:
   - Save tampered requests and responses.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html

Order Total: $0.01
```

**Remediation**:
- Validate integrity server-side:
  ```javascript
  const crypto = require('crypto');
  const data = `${req.body.item_id}${req.body.quantity}${req.body.price}`;
  const hash = crypto.createHmac('sha256', 'secret-key').update(data).digest('hex');
  if (req.body.hash !== hash) {
      res.status(400).send('Invalid data');
  }
  ```

### **3. Test API Integrity with Postman**

Test API endpoints for weak integrity checks on critical data.

**Steps**:
1. **Identify API Endpoints**:
   - Use Burp Suite to find APIs (e.g., `/api/v1/order`).
   - Import endpoints into Postman.
2. **Tamper with Parameters**:
   - Send requests with modified data (e.g., `PUT /api/v1/order { "total": 0.01, "hash": "unchanged" }`).
   - Test missing or invalid integrity fields (e.g., omit `signature`).
3. **Analyze Response**:
   - Check if the API accepts tampered data (e.g., processes incorrect total).
   - Look for error messages exposing integrity logic.
4. **Document Findings**:
   - Save API requests and responses in Postman.

**Example Vulnerable API Response**:
```json
{
  "status": "success",
  "total": 0.01
}
```

**Remediation**:
- Enforce API integrity:
  ```python
  import hmac
  import hashlib
  secret = b'secret-key'
  data = f"{request.json['item_id']}{request.json['quantity']}{request.json['price']}".encode()
  expected_hash = hmac.new(secret, data, hashlib.sha256).hexdigest()
  if request.json.get('hash') != expected_hash:
      return jsonify({'error': 'Data tampered'}), 400
  ```

### **4. Bypass Client-Side Integrity Checks with Browser Developer Tools**

Test whether client-side integrity mechanisms can be bypassed.

**Steps**:
1. **Open Developer Tools**:
   - Press `F12` on `http://example.com/order` and go to “Elements” or “Network” tab.
   - Locate form fields or scripts generating integrity values (e.g., `<input name="hash" value="abc123">`).
2. **Modify Values**:
   - Change critical fields (e.g., `<input name="price" value="99.99">` to `value="0.01"`).
   - Leave `hash` unchanged or remove it.
   - Submit the form.
3. **Analyze Response**:
   - Check if the server accepts tampered data.
   - Note any errors or unexpected behavior.
4. **Document Findings**:
   - Save screenshots and server responses.

**Example Vulnerable Finding**:
- Modified: `<input name="price" value="0.01">`
- Response: Order total updated to $0.01.

**Remediation**:
- Avoid client-side integrity checks:
  ```php
  // Generate hash server-side
  $data = $item_id . $quantity . $price;
  $hash = hash_hmac('sha256', $data, 'secret-key');
  // Validate on submission
  if ($_POST['hash'] !== hash_hmac('sha256', $_POST['data'], 'secret-key')) {
      die('Tampering detected');
  }
  ```

### **5. Script Tampering Tests with Python Requests**

Automate tampering tests to evaluate integrity checks across multiple scenarios.

**Steps**:
1. **Write Python Script**:
   - Create a script to tamper with data:
     ```python
     import requests
     import hmac
     import hashlib

     url = 'http://example.com/order/submit'
     payloads = [
         {'item_id': '123', 'quantity': 2, 'price': 0.01, 'hash': '5f4dcc3b5aa765d61d8327deb882cf99'},
         {'item_id': '123', 'quantity': -1, 'price': 99.99, 'hash': 'unchanged'},
         {'item_id': '123', 'quantity': 2, 'price': 99.99}  # Missing hash
     ]

     for payload in payloads:
         response = requests.post(url, data=payload)
         print(f"Payload: {payload}")
         print(f"Response: {response.text}\n")
     ```
2. **Run Script**:
   - Execute: `python3 test.py`.
   - Analyze responses for acceptance of tampered data.
3. **Verify Findings**:
   - Cross-check with Burp Suite results.
4. **Document Results**:
   - Save script output and responses.

**Example Vulnerable Output**:
```
Payload: {'item_id': '123', 'quantity': 2, 'price': 0.01, 'hash': '5f4dcc3b5aa765d61d8327deb882cf99'}
Response: {"status": "success", "total": 0.01}
```

**Remediation**:
- Implement robust integrity checks:
  ```javascript
  const data = `${payload.item_id}${payload.quantity}${payload.price}`;
  const hash = require('crypto').createHmac('sha256', 'secret').update(data).digest('hex');
  if (!payload.hash || payload.hash !== hash) {
      throw new Error('Data tampered');
  }
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-BUSL-03 with practical scenarios based on common integrity check vulnerabilities observed in penetration testing.

### **Test 1: Tamper with E-commerce Order Total**

Test whether modifying an order total bypasses integrity checks.

**Steps**:
1. **Capture Request**:
   - Use Burp Suite to capture:
     ```
     POST /order/submit HTTP/1.1
     Host: example.com
     item_id=123&quantity=2&total=199.98&hash=abc123
     ```
2. **Tamper with Total**:
   - In Repeater, change `total=199.98` to `total=0.01`, keeping `hash` unchanged.
   - Send request.
3. **Verify**:
   - Check if order total reflects $0.01.

**Example Insecure Finding**:
- Response: `Order Total: $0.01`

**Example Secure Configuration**:
- Validate total with HMAC:
  ```php
  $data = $_POST['item_id'] . $_POST['quantity'] . $_POST['total'];
  $hash = hash_hmac('sha256', $data, 'secret');
  if ($_POST['hash'] !== $hash) {
      die('Invalid total');
  }
  ```

**Remediation**:
- Use server-side HMACs for all critical data.
- Log tampering attempts.

### **Test 2: Modify User Role in API Request**

Test whether tampering with a user role bypasses integrity checks.

**Steps**:
1. **Capture API Request**:
   - In Postman, send:
     ```json
     PUT /api/v1/profile
     {"user_id": 123, "role": "user", "signature": "xyz789"}
     ```
2. **Tamper with Role**:
   - Change `"role": "user"` to `"role": "admin"`, keeping `signature` unchanged.
   - Send request.
3. **Verify**:
   - Check if admin role is applied.

**Example Insecure Finding**:
- Response: `{"status": "Profile updated", "role": "admin"}`

**Example Secure Configuration**:
- Validate signature:
  ```python
  data = f"{request.json['user_id']}{request.json['role']}".encode()
  signature = hmac.new(b'secret', data, hashlib.sha256).hexdigest()
  if request.json.get('signature') != signature:
      return jsonify({'error': 'Invalid signature'}), 400
  ```

**Remediation**:
- Use cryptographic signatures for role changes.
- Restrict role updates to authorized users.

### **Test 3: Corrupt Hidden Form Field**

Test whether tampering with a hidden form field bypasses integrity checks.

**Steps**:
1. **Inspect Form**:
   - In Developer Tools, find: `<input type="hidden" name="discount" value="10">` with `<input name="checksum" value="def456">`.
   - Change `discount` to `100`.
2. **Submit Form**:
   - Submit without updating `checksum`.
3. **Verify**:
   - Check if 100% discount is applied.

**Example Insecure Finding**:
- Response: `Order Total: $0.00`

**Example Secure Configuration**:
- Validate checksum:
  ```javascript
  const data = req.body.discount;
  const checksum = crypto.createHash('sha256').update(data + 'secret').digest('hex');
  if (req.body.checksum !== checksum) {
      res.status(400).send('Invalid checksum');
  }
  ```

**Remediation**:
- Use server-side checksums.
- Avoid hidden fields for critical data.

### **Test 4: Remove Integrity Field**

Test whether removing an integrity field allows tampering.

**Steps**:
1. **Capture Request**:
   - Use OWASP ZAP to capture:
     ```
     POST /transaction HTTP/1.1
     Host: example.com
     amount=50.00&account=123&hash=ghi789
     ```
2. **Remove Hash**:
   - Delete `hash=ghi789` and change `amount=50.00` to `amount=0.01`.
   - Send request.
3. **Verify**:
   - Check if transaction processes with $0.01.

**Example Insecure Finding**:
- Response: `Transaction successful: $0.01`

**Example Secure Configuration**:
- Require hash:
  ```php
  if (!isset($_POST['hash'])) {
      die('Missing integrity check');
  }
  ```

**Remediation**:
- Mandate integrity fields.
- Reject requests with missing or invalid hashes.

## **Additional Tips**

- **Understand Data Flow**: Map critical data (e.g., prices, roles) to identify where integrity checks are needed.
- **Combine Tools**: Use Burp Suite for initial capture, Postman for APIs, and Python for automation.
- **Gray-Box Testing**: If documentation is available, check for HMAC or signature implementations.
- **Document Thoroughly**: Save all tampered requests, responses, and screenshots in a report.
- **Bypass Defenses**: Test edge cases (e.g., partial tampering, invalid formats) to uncover weak checks.
- **Stay Ethical**: Obtain explicit permission for active testing and avoid disrupting live systems.
- **Follow Best Practices**: Refer to OWASP’s Business Logic Testing section for additional techniques: [OWASP WSTG Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/).