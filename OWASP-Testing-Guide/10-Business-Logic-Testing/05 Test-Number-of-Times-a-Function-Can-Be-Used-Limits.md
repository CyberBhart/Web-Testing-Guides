# **Test Number of Times a Function Can Be Used Limits**

## **Overview**

Testing the number of times a function can be used limits (WSTG-BUSL-05) involves assessing whether a web application enforces restrictions on how many times a specific function, such as password resets, coupon redemptions, or form submissions, can be executed within a given timeframe or session. According to OWASP, vulnerabilities arise when applications fail to implement rate-limiting, throttling, or usage caps, allowing attackers to abuse functions through brute-force attacks, resource exhaustion, or unauthorized actions. This test focuses on identifying weaknesses in usage limits that could lead to security or operational issues.

**Impact**: Weak function usage limits can lead to:
- Brute-force attacks (e.g., guessing password reset tokens).
- Resource exhaustion (e.g., spamming form submissions).
- Financial loss (e.g., redeeming a single-use coupon multiple times).
- Denial-of-service (DoS) by overwhelming critical functions.

This guide provides a step-by-step methodology for testing function usage limits, adhering to OWASP’s WSTG-BUSL-05, with practical tools, at least two specific commands per tool for real security testing, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing function usage limits, with at least two specific commands or configurations provided for each to enable real security testing:

- **Burp Suite Community Edition**: Intercepts and automates repeated requests to test rate limits.
- **cURL**: Command-line tool for sending rapid or repeated HTTP requests.
- **Postman**: Tool for testing API endpoints with repeated function calls.
- **Apache JMeter**: Load testing tool for simulating multiple function executions.
- **Python Requests Library**: Python library for scripting automated, repeated requests.

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

This methodology follows OWASP’s black-box approach for WSTG-BUSL-05, focusing on repeatedly executing a function to test whether the application enforces usage limits or rate-limiting mechanisms.

### **1. Identify Restricted Functions with Burp Suite**

Locate functions that should have usage limits, such as password resets or coupon redemptions.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Interact with the Application**:
   - Perform actions like requesting a password reset, redeeming a coupon, or submitting a form.
   - Capture requests in Burp Suite’s “HTTP History”.
3. **Identify Restricted Functions**:
   - Look for endpoints like `POST /reset-password`, `POST /coupon/redeem`, or `POST /form/submit`.
   - Note parameters (e.g., `email`, `coupon_code`) and session tokens.
4. **Document Findings**:
   - Save request details in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Capture a password reset request and send to Intruder for repeated testing:
  ```
  Right-click request in "HTTP History" -> Send to Intruder -> Positions tab -> Clear § -> Select email parameter (e.g., email=user@example.com) -> Add § -> Payloads tab -> Simple list -> Add "user@example.com" -> Start Attack
  ```
- **Command 2**: Use Repeater to manually resend a coupon redemption request multiple times:
  ```
  Right-click request (e.g., POST /coupon/redeem) -> Send to Repeater -> Click "Send" 10 times in quick succession -> Observe responses in "Response" pane
  ```

**Example Request**:
```
POST /reset-password HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

email=user@example.com
```

**Remediation**:
- Implement rate-limiting:
  ```php
  $cache = new Cache();
  $key = 'reset_' . md5($email);
  if ($cache->get($key) > 5) {
      die('Too many attempts');
  }
  $cache->increment($key, 1, 3600); // 1-hour limit
  ```

### **2. Test Rate Limits with cURL**

Send repeated requests to test whether the application enforces function usage limits.

**Steps**:
1. **Capture Request Details**:
   - Use Burp Suite to note the request structure (e.g., headers, parameters).
2. **Send Repeated Requests**:
   - Use cURL to send multiple requests rapidly.
   - Observe responses for rate-limiting or blocking.
3. **Analyze Response**:
   - Check for HTTP 429 (Too Many Requests), errors, or continued processing.
   - Verify if the function executes beyond expected limits.
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Send 10 password reset requests in a loop:
  ```bash
  for i in {1..10}; do curl -X POST -d "email=user@example.com" http://example.com/reset-password; sleep 0.1; done
  ```
- **Command 2**: Attempt coupon redemption 5 times with the same code:
  ```bash
  for i in {1..5}; do curl -X POST -d "coupon_code=SAVE10" -b "session=abc123" http://example.com/coupon/redeem; done
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
Password reset link sent (10 times)
```

**Remediation**:
- Use server-side throttling:
  ```javascript
  const rateLimit = require('express-rate-limit');
  app.use('/reset-password', rateLimit({
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 5 // 5 requests
  }));
  ```

### **3. Test API Function Limits with Postman**

Test API endpoints for usage limit enforcement.

**Steps**:
1. **Identify API Endpoints**:
   - Use Burp Suite to find APIs (e.g., `/api/v1/reset-password`).
   - Import into Postman.
2. **Send Repeated Requests**:
   - Create a Postman Collection to repeat requests.
   - Run with minimal delay to simulate rapid execution.
3. **Analyze Response**:
   - Check for rate-limiting responses or continued processing.
   - Verify if the function executes beyond limits.
4. **Document Findings**:
   - Save Postman run results.

**Postman Commands**:
- **Command 1**: Create a Collection to send 10 password reset requests:
  ```
  New Collection -> Add Request (POST http://example.com/api/v1/reset-password) -> Body: {"email": "user@example.com"} -> Save -> Collection Runner -> Select Collection -> Set Iterations to 10 -> Run
  ```
- **Command 2**: Test coupon redemption with 5 rapid API calls:
  ```
  New Request (POST http://example.com/api/v1/coupon/redeem) -> Body: {"coupon_code": "SAVE10"} -> Headers: Cookie: session=abc123 -> Tests tab: pm.test("Run next", function() { postman.setNextRequest(pm.info.requestName); }) -> Save -> Send 5 times manually or use Collection Runner
  ```

**Example Vulnerable API Response**:
```json
{
  "status": "success",
  "message": "Coupon applied (5 times)"
}
```

**Remediation**:
- Enforce API rate limits:
  ```python
  from flask_limiter import Limiter
  limiter = Limiter(app, key_func=lambda: request.json.get('email'))
  @limiter.limit("5/hour")
  @app.route('/api/v1/reset-password', methods=['POST'])
  def reset_password():
      return jsonify({"status": "success"})
  ```

### **4. Simulate High-Volume Requests with Apache JMeter**

Use JMeter to test function limits under high-frequency requests.

**Steps**:
1. **Create JMeter Test Plan**:
   - Add a Thread Group with 10 threads and 1 loop.
   - Add an HTTP Request sampler for the target function (e.g., `POST /reset-password`).
2. **Run Test**:
   - Start JMeter and execute the test plan.
3. **Analyze Results**:
   - Check for successful executions beyond expected limits.
   - Look for HTTP 429 or error responses.
4. **Document Findings**:
   - Save JMeter results.

**JMeter Commands**:
- **Command 1**: Configure Thread Group to send 10 password reset requests:
  ```
  JMeter GUI -> File -> New -> Add -> Threads (Users) -> Thread Group -> Number of Threads: 10, Ramp-Up Period: 0, Loop Count: 1 -> Add -> Sampler -> HTTP Request -> Server: example.com, Path: /reset-password, Method: POST, Parameters: email=user@example.com -> Run
  ```
- **Command 2**: Test coupon redemption with 5 concurrent requests:
  ```
  JMeter GUI -> Thread Group -> Number of Threads: 5, Ramp-Up Period: 0, Loop Count: 1 -> HTTP Request -> Server: example.com, Path: /coupon/redeem, Method: POST, Parameters: coupon_code=SAVE10 -> Add -> Config Element -> HTTP Cookie Manager -> Cookie: session=abc123 -> Run
  ```

**Example Vulnerable Result**:
- 10 requests -> All return `HTTP 200: Reset link sent`.

**Remediation**:
- Implement database-based limits:
  ```sql
  INSERT INTO rate_limits (user_id, action, count, expiry) 
  VALUES (123, 'reset_password', 1, NOW() + INTERVAL 1 HOUR)
  ON DUPLICATE KEY UPDATE count = count + 1;
  IF (SELECT count FROM rate_limits WHERE user_id = 123 AND action = 'reset_password') > 5 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Too many attempts';
  END IF;
  ```

### **5. Automate Repeated Requests with Python Requests**

Script automated tests to evaluate function usage limits.

**Steps**:
1. **Write Python Script**:
   - Create a script to send repeated requests:
     ```python
     import requests
     import time

     url = 'http://example.com/reset-password'
     data = {'email': 'user@example.com'}
     cookies = {'session': 'abc123'}
     responses = []

     for _ in range(10):
         response = requests.post(url, data=data, cookies=cookies)
         responses.append(response.text)
         time.sleep(0.1)  # Simulate rapid requests
         print(f"Attempt {_ + 1}: {response.status_code} - {response.text}")

     print(f"Successful attempts: {len([r for r in responses if 'success' in r.lower()])}")
     ```
2. **Run Script**:
   - Execute: `python3 test.py`.
   - Analyze for successful executions beyond limits.
3. **Verify Findings**:
   - Cross-check with Burp Suite or JMeter results.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run the above script to test password reset limits:
  ```bash
  python3 test.py
  ```
- **Command 2**: Modify the script to test coupon redemption and run:
  ```python
  import requests
  url = 'http://example.com/coupon/redeem'
  data = {'coupon_code': 'SAVE10'}
  cookies = {'session': 'abc123'}
  for _ in range(5):
      response = requests.post(url, data=data, cookies=cookies)
      print(f"Attempt {_ + 1}: {response.status_code} - {response.text}")
  ```
  ```bash
  python3 test_coupon.py
  ```

**Example Vulnerable Output**:
```
Attempt 1: 200 - {"status": "success"}
...
Attempt 10: 200 - {"status": "success"}
Successful attempts: 10
```

**Remediation**:
- Use Redis for rate-limiting:
  ```python
  import redis
  r = redis.Redis(host='localhost', port=6379)
  key = f"reset:{email}"
  if r.exists(key) and int(r.get(key)) >= 5:
      raise ValueError("Too many attempts")
  r.incr(key)
  r.expire(key, 3600)  # 1-hour expiry
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-BUSL-05 with practical scenarios based on common function usage limit vulnerabilities observed in penetration testing.

### **Test 1: Password Reset Brute-Force**

Test whether the application allows unlimited password reset requests.

**Steps**:
1. **Capture Request**:
   - Use Burp Suite to capture:
     ```
     POST /reset-password HTTP/1.1
     Host: example.com
     email=user@example.com
     ```
2. **Send Repeated Requests**:
   - Use cURL command: `for i in {1..10}; do curl -X POST -d "email=user@example.com" http://example.com/reset-password; sleep 0.1; done`.
3. **Verify**:
   - Check if all 10 requests succeed.

**Example Insecure Finding**:
- Response: `Reset link sent` for all 10 attempts.

**Example Secure Configuration**:
- Limit resets:
  ```php
  if (Cache::get('reset_count_' . $email, 0) >= 5) {
      http_response_code(429);
      die('Too many reset attempts');
  }
  Cache::increment('reset_count_' . $email);
  ```

**Remediation**:
- Enforce rate limits (e.g., 5/hour).
- Notify users of excessive attempts.

### **Test 2: Coupon Redemption Abuse**

Test whether a single-use coupon can be redeemed multiple times.

**Steps**:
1. **Capture Request**:
   - Use Postman to send:
     ```json
     POST /api/v1/coupon/redeem
     {"coupon_code": "SAVE10"}
     ```
2. **Send Repeated Requests**:
   - Use Postman Collection Runner with 5 iterations.
3. **Verify**:
   - Check if coupon is applied multiple times.

**Example Insecure Finding**:
- Response: `Coupon applied` for all 5 attempts.

**Example Secure Configuration**:
- Track coupon usage:
  ```javascript
  const coupon = await db.query('SELECT uses FROM coupons WHERE code = ?', [code]);
  if (coupon.uses <= 0) {
      res.status(400).send('Coupon exhausted');
  }
  await db.query('UPDATE coupons SET uses = uses - 1 WHERE code = ?', [code]);
  ```

**Remediation**:
- Use database-driven usage tracking.
- Expire coupons after use.

### **Test 3: Form Submission Spam**

Test whether a contact form allows unlimited submissions.

**Steps**:
1. **Capture Request**:
   - Use JMeter to configure: `POST /contact` with `message=Test`.
2. **Send Repeated Requests**:
   - Use JMeter Thread Group with 10 threads.
3. **Verify**:
   - Check if all submissions are processed.

**Example Insecure Finding**:
- 10 submissions -> All return `HTTP 200: Message sent`.

**Example Secure Configuration**:
- Rate-limit forms:
  ```python
  from flask import session
  if session.get('form_count', 0) >= 3:
      return jsonify({'error': 'Too many submissions'}), 429
  session['form_count'] = session.get('form_count', 0) + 1
  ```

**Remediation**:
- Implement CAPTCHA or rate-limiting.
- Log excessive submissions.

### **Test 4: API Token Request Abuse**

Test whether an API token issuance endpoint allows unlimited requests.

**Steps**:
1. **Write Python Script**:
   - Use Python command above to send 10 token requests.
2. **Run Script**:
   - Execute: `python3 test.py`.
3. **Verify**:
   - Check if multiple tokens are issued.

**Example Insecure Finding**:
- 10 requests -> 10 tokens issued.

**Example Secure Configuration**:
- Limit token issuance:
  ```javascript
  const redis = require('redis').createClient();
  const key = `token:${user_id}`;
  if (await redis.get(key) >= 5) {
      throw new Error('Too many token requests');
  }
  await redis.incr(key);
  await redis.expire(key, 3600);
  ```

**Remediation**:
- Cap token requests per user.
- Invalidate old tokens.

## **Additional Tips**

- **Map Functions**: Identify functions with potential limits (e.g., resets, submissions) to target for testing.
- **Combine Tools**: Use Burp Suite for initial capture, JMeter for high-volume tests, and Python for automation.
- **Gray-Box Testing**: If documentation is available, check for rate-limiting or throttling mechanisms.
- **Document Thoroughly**: Save all commands, responses, and test results in a report.
- **Bypass Defenses**: Test with different sessions or IPs to evade client-side limits.
- **Stay Ethical**: Obtain explicit permission for active testing, especially high-frequency tests, to avoid disrupting live systems.
- **Follow Best Practices**: Refer to OWASP’s Business Logic Testing section for additional techniques: [OWASP WSTG Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/).