# **Test Defenses Against Application Misuse**

## **Overview**

Testing defenses against application misuse (WSTG-BUSL-07) involves assessing whether a web application has active mechanisms to detect and respond to misuse, such as malicious inputs, abnormal usage patterns, or attempts to exploit legitimate functionality. According to OWASP, misuse can include actions like submitting invalid data, rapid automated requests, or performing unexpected operations, which may indicate an attack. Weak or absent defenses allow attackers to probe for vulnerabilities without detection, leaving the application owner unaware of the threat. This test focuses on verifying whether the application monitors and mitigates misuse, particularly in authenticated areas, though public areas may also be tested for rate-limiting or scraping defenses.

**Impact**: Insufficient defenses against misuse can lead to:
- Undetected brute-force attacks (e.g., credential stuffing).
- Resource exhaustion (e.g., DoS via excessive requests).
- Exploitation of legitimate features (e.g., spamming contact forms).
- Increased attack surface due to unmonitored malicious activity.

This guide provides a step-by-step methodology for testing defenses against application misuse, adhering to OWASP’s WSTG-BUSL-07, with practical tools, at least two specific commands or configurations per tool for real security testing, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing defenses against application misuse, with at least two specific commands or configurations provided for each to enable real security testing:

- **Burp Suite Community Edition**: Intercepts and automates requests to simulate misuse patterns.
- **cURL**: Command-line tool for sending rapid or malformed requests to test defenses.
- **Postman**: Tool for testing API endpoints with abusive inputs or patterns.
- **Apache JMeter**: Load testing tool for simulating high-frequency or malicious requests.
- **Python Requests Library**: Python library for scripting automated misuse scenarios.

### **Tool Setup Instructions**

1. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
   - Verify: Start Burp and check proxy functionality.
2. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
3. **Postman**:
   - Download from [postman.com](https://www.postman.com/downloads/).
   - Install and create a free account.
   - Verify: Open Postman and check version.
4. **Apache JMeter**:
   - Download from [jmeter.apache.org](https://jmeter.apache.org/download_jmeter.cgi).
   - Extract and run: `bin/jmeter.sh` (Linux) or `bin/jmeter.bat` (Windows).
   - Verify: Check JMeter GUI.
5. **Python Requests Library**:
   - Install Python: `sudo apt install python3`.
   - Install Requests: `pip install requests`.
   - Verify: `python3 -c "import requests; print(requests.__version__)"`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-BUSL-07, focusing on simulating misuse patterns (e.g., excessive requests, malformed inputs, or abnormal actions) to evaluate the application’s detection and response mechanisms.

### **1. Simulate Excessive Requests with Burp Suite**

Test whether the application detects and blocks rapid or excessive requests, such as login attempts or form submissions.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Capture Request**:
   - Perform an action like logging in or submitting a form.
   - Capture the request in Burp Suite’s “HTTP History” (e.g., `POST /login`).
3. **Simulate Misuse**:
   - Use Intruder to send multiple requests rapidly.
   - Observe responses for rate-limiting or account lockout.
4. **Analyze Response**:
   - Check for HTTP 429 (Too Many Requests), account lockout, or continued processing.
   - Verify if defenses trigger (e.g., CAPTCHA, IP block).
5. **Document Findings**:
   - Save Intruder results and responses.

**Burp Suite Commands**:
- **Command 1**: Send 50 login attempts to test rate-limiting:
  ```
  Right-click POST /login in HTTP History -> Send to Intruder -> Positions tab -> Clear § -> Select password parameter (e.g., password=pass123) -> Add § -> Payloads tab -> Simple list -> Add "pass123" -> Options tab -> Set Threads to 10 -> Start Attack
  ```
- **Command 2**: Use Scanner to simulate aggressive form submissions:
  ```
  Target tab -> Site Map -> Right-click example.com -> Engagement Tools -> Active Scan -> Select /contact endpoint -> Run Scan -> Check Issues tab for rate-limiting or misuse detection
  ```

**Example Request**:
```
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=user@example.com&password=pass123
```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
Login failed (50 times, no lockout)
```

**Remediation**:
- Implement account lockout:
  ```php
  $cache = new Cache();
  $key = 'login_attempts_' . $username;
  if ($cache->get($key, 0) >= 5) {
      die('Account locked for 30 minutes');
  }
  $cache->increment($key, 1, 1800); // 30-minute window
  ```

### **2. Test with Malformed Inputs Using cURL**

Send malformed or unexpected inputs to test whether the application detects and handles misuse.

**Steps**:
1. **Identify Input Points**:
   - Use Burp Suite to find forms or API endpoints (e.g., `/contact`, `/api/v1/submit`).
2. **Send Malformed Requests**:
   - Use cURL to submit invalid or malicious data (e.g., oversized strings, SQL injection payloads).
   - Repeat to test detection mechanisms.
3. **Analyze Response**:
   - Check for input validation, error handling, or blocking.
   - Look for verbose errors exposing misuse detection logic.
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Submit an oversized input to a contact form:
  ```bash
  curl -X POST -d "message=$(printf 'A%.0s' {1..10000})" http://example.com/contact
  ```
- **Command 2**: Send a malicious input to test SQL injection detection:
  ```bash
  curl -X POST -d "username=admin' OR '1'='1" -b "session=abc123" http://example.com/login
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
Content-Type: text/html
Error: Input too long (no blocking)
```

**Remediation**:
- Validate and sanitize inputs:
  ```javascript
  const sanitize = require('sanitize-html');
  if (req.body.message.length > 1000 || !sanitize(req.body.message)) {
      res.status(400).send('Invalid input');
  }
  ```

### **3. Test API Misuse with Postman**

Test API endpoints for defenses against rapid or malicious requests.

**Steps**:
1. **Identify API Endpoints**:
   - Use Burp Suite to find APIs (e.g., `/api/v1/login`).
   - Import into Postman.
2. **Simulate Misuse**:
   - Send rapid requests or malformed payloads.
   - Test for rate-limiting or input validation.
3. **Analyze Response**:
   - Check for HTTP 429, error messages, or continued processing.
   - Verify if defenses trigger (e.g., temporary bans).
4. **Document Findings**:
   - Save Postman run results.

**Postman Commands**:
- **Command 1**: Send 10 rapid login requests to test rate-limiting:
  ```
  New Collection -> Add Request (POST http://example.com/api/v1/login) -> Body: {"username": "user@example.com", "password": "pass123"} -> Save -> Collection Runner -> Select Collection -> Set Iterations to 10, Delay to 0ms -> Run
  ```
- **Command 2**: Test with a malicious JSON payload:
  ```
  New Request -> POST http://example.com/api/v1/submit -> Body: {"data": "<script>alert('xss')</script>"} -> Headers: Cookie: session=abc123 -> Send
  ```

**Example Vulnerable API Response**:
```json
{
  "status": "success",
  "message": "Request processed (10 times, no limits)"
}
```

**Remediation**:
- Enforce API rate limits:
  ```python
  from flask_limiter import Limiter
  limiter = Limiter(app, key_func=lambda: request.remote_addr)
  @limiter.limit("10/minute")
  @app.route('/api/v1/login', methods=['POST'])
  def login():
      return jsonify({"status": "failed"})
  ```

### **4. Simulate High-Volume Misuse with Apache JMeter**

Use JMeter to test defenses against high-frequency or abusive requests.

**Steps**:
1. **Create JMeter Test Plan**:
   - Add a Thread Group with 20 threads and 1 loop.
   - Add an HTTP Request sampler for a target endpoint (e.g., `POST /contact`).
2. **Simulate Misuse**:
   - Configure rapid or malformed requests.
   - Run the test plan.
3. **Analyze Results**:
   - Check for rate-limiting, blocking, or error responses.
   - Verify if requests are processed beyond expected limits.
4. **Document Findings**:
   - Save JMeter results.

**JMeter Commands**:
- **Command 1**: Send 20 contact form submissions to test rate-limiting:
  ```
  JMeter GUI -> File -> New -> Add -> Threads (Users) -> Thread Group -> Number of Threads: 20, Ramp-Up Period: 0, Loop Count: 1 -> Add -> Sampler -> HTTP Request -> Server: example.com, Path: /contact, Method: POST, Parameters: message=TestMessage -> Run
  ```
- **Command 2**: Test login with malicious inputs:
  ```
  JMeter GUI -> Thread Group -> Number of Threads: 10, Ramp-Up Period: 0, Loop Count: 1 -> HTTP Request -> Server: example.com, Path: /login, Method: POST, Parameters: username=admin' OR '1'='1, password=pass123 -> Add -> Config Element -> HTTP Cookie Manager -> Cookie: session=abc123 -> Run
  ```

**Example Vulnerable Result**:
- 20 requests -> All return `HTTP 200: Message sent`.

**Remediation**:
- Implement IP-based throttling:
  ```sql
  INSERT INTO request_limits (ip, count, expiry)
  VALUES ('192.168.1.1', 1, NOW() + INTERVAL 1 MINUTE)
  ON DUPLICATE KEY UPDATE count = count + 1;
  IF (SELECT count FROM request_limits WHERE ip = '192.168.1.1') > 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Too many requests';
  END IF;
  ```

### **5. Script Misuse Scenarios with Python Requests**

Automate tests to simulate misuse and evaluate detection mechanisms.

**Steps**:
1. **Write Python Script**:
   - Create a script to send rapid or malicious requests:
     ```python
     import requests
     import time

     url = 'http://example.com/login'
     payloads = [
         {'username': 'user@example.com', 'password': 'pass123'},
         {'username': 'admin\' OR \'1\'=\'1', 'password': 'pass123'},
         {'username': 'a' * 10000, 'password': 'pass123'}
     ]
     cookies = {'session': 'abc123'}
     responses = []

     for i, payload in enumerate(payloads * 5):  # Repeat each payload 5 times
         response = requests.post(url, data=payload, cookies=cookies)
         responses.append(response.text)
         print(f"Attempt {i + 1}: {response.status_code} - {response.text[:100]}")
         time.sleep(0.1)  # Simulate rapid requests

     print(f"Successful attempts: {len([r for r in responses if 'success' in r.lower()])}")
     ```
2. **Run Script**:
   - Execute: `python3 test.py`.
   - Analyze for detection or blocking.
3. **Verify Findings**:
   - Cross-check with Burp Suite or JMeter results.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run the above script to test login misuse:
  ```bash
  python3 test.py
  ```
- **Command 2**: Modify the script to test form submission with oversized data and run:
  ```python
  import requests
  url = 'http://example.com/contact'
  data = {'message': 'A' * 10000}
  cookies = {'session': 'abc123'}
  for _ in range(5):
      response = requests.post(url, data=data, cookies=cookies)
      print(f"Attempt {_ + 1}: {response.status_code} - {response.text[:100]}")
  ```
  ```bash
  python3 test_contact.py
  ```

**Example Vulnerable Output**:
```
Attempt 1: 200 - {"status": "failed"}
...
Attempt 15: 200 - {"status": "failed"}
Successful attempts: 0 (no blocking)
```

**Remediation**:
- Use anomaly detection:
  ```python
  from redis import Redis
  redis = Redis(host='localhost', port=6379)
  key = f"requests:{request.remote_addr}"
  if redis.exists(key) and int(redis.get(key)) >= 10:
      return jsonify({'error': 'Suspicious activity detected'}), 429
  redis.incr(key)
  redis.expire(key, 60)  # 1-minute window
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-BUSL-07 with practical scenarios based on common application misuse vulnerabilities observed in penetration testing.

### **Test 1: Brute-Force Login Attempts**

Test whether the application detects and blocks excessive login attempts.

**Steps**:
1. **Capture Request**:
   - Use Burp Suite to capture: `POST /login`.
2. **Simulate Brute-Force**:
   - Use Burp Intruder command: Send 50 login attempts.
3. **Verify**:
   - Check for account lockout, CAPTCHA, or HTTP 429.

**Example Insecure Finding**:
- Response: `Login failed` for all 50 attempts, no lockout.

**Example Secure Configuration**:
- Lock accounts:
  ```javascript
  const redis = require('redis').createClient();
  const key = `login:${username}`;
  if (await redis.get(key) >= 5) {
      throw new Error('Account locked');
  }
  await redis.incr(key);
  await redis.expire(key, 1800);
  ```

**Remediation**:
- Implement account lockout after 5 failed attempts.
- Notify users of lockouts.

### **Test 2: Malformed Input in Contact Form**

Test whether the application detects oversized or malicious form inputs.

**Steps**:
1. **Capture Request**:
   - Use cURL: `curl -X POST -d "message=$(printf 'A%.0s' {1..10000})" http://example.com/contact`.
2. **Send Malformed Input**:
   - Repeat 5 times.
3. **Verify**:
   - Check for input rejection or blocking.

**Example Insecure Finding**:
- Response: `Message sent` with no validation.

**Example Secure Configuration**:
- Validate input length:
  ```php
  if (strlen($_POST['message']) > 1000) {
      http_response_code(400);
      die('Input too long');
  }
  ```

**Remediation**:
- Enforce input size limits.
- Sanitize inputs to prevent injection.

### **Test 3: API Request Flood**

Test whether an API endpoint detects rapid request flooding.

**Steps**:
1. **Capture Request**:
   - Use Postman to send: `POST /api/v1/submit`.
2. **Flood Endpoint**:
   - Use Postman Collection Runner with 10 iterations.
3. **Verify**:
   - Check for HTTP 429 or IP blocking.

**Example Insecure Finding**:
- Response: `Request processed` for all 10 requests.

**Example Secure Configuration**:
- Rate-limit API:
  ```python
  from flask import request
  cache = {}
  ip = request.remote_addr
  if ip in cache and cache[ip] >= 10:
      return jsonify({'error': 'Too many requests'}), 429
  cache[ip] = cache.get(ip, 0) + 1
  ```

**Remediation**:
- Implement rate-limiting (e.g., 10 requests/minute).
- Use WAF for request monitoring.

### **Test 4: Abnormal API Payload**

Test whether an API detects malicious payloads.

**Steps**:
1. **Send Malicious Payload**:
   - Use Python command: `python3 test.py` with malicious input.
2. **Analyze Response**:
   - Check for payload rejection or account suspension.
3. **Verify**:
   - Confirm if misuse is logged or blocked.

**Example Insecure Finding**:
- Response: `HTTP 500` with no blocking.

**Example Secure Configuration**:
- Detect malicious inputs:
  ```javascript
  if (req.body.data.match(/[<>\;]/)) {
      res.status(400).send('Invalid input detected');
  }
  ```

**Remediation**:
- Implement input validation.
- Log suspicious requests for analysis.

## **Additional Tips**

- **Identify Critical Functions**: Target functions prone to misuse (e.g., login, forms, APIs) for testing.
- **Combine Tools**: Use Burp Suite for initial capture, JMeter for high-volume tests, and Python for malicious inputs.
- **Gray-Box Testing**: If documentation is available, check for rate-limiting, WAF, or anomaly detection.
- **Document Thoroughly**: Save all commands, responses, and test results in a report.
- **Bypass Defenses**: Test with different IPs, sessions, or payloads to evade detection.
- **Stay Ethical**: Obtain explicit permission for active testing, especially high-frequency or malicious tests, to avoid disrupting live systems.
- **Follow Best Practices**: Refer to OWASP’s Business Logic Testing section for additional techniques: [OWASP WSTG Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/).