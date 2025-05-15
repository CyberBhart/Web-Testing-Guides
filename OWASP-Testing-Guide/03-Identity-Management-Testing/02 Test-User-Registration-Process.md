# **Test User Registration Process**

## **Overview**

Testing the User Registration Process (WSTG-IDNT-02) involves assessing a web application’s registration functionality to ensure it securely handles user onboarding, enforces strong controls, and prevents vulnerabilities such as unauthorized account creation, privilege escalation, or account enumeration. According to OWASP, weaknesses in registration processes can allow attackers to create accounts with elevated privileges, exploit weak password policies, or enumerate existing users, compromising security and integrity. This test focuses on validating input handling, role assignments, password policies, verification mechanisms, and anti-automation controls to identify and mitigate risks in the registration process.

**Impact**: Weaknesses in the user registration process can lead to:
- Unauthorized account creation with administrative privileges.
- Account enumeration through verbose error messages, aiding targeted attacks.
- Security bypasses due to weak passwords or injection vulnerabilities.
- System overload or abuse from automated account creation.

This guide provides a practical, hands-on methodology for testing the user registration process, adhering to OWASP’s WSTG-IDNT-02, with detailed tool setups, at least two specific commands or configurations per tool, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing the user registration process, with at least two specific commands or configurations per tool for real security testing:

- **Burp Suite Community Edition**: Intercepts and manipulates registration requests to test input validation and role assignment.
- **Postman**: Tests API-based registration endpoints for vulnerabilities.
- **cURL**: Sends crafted registration requests to analyze responses and error messages.
- **Browser Developer Tools**: Inspects client-side validation and hidden fields in registration forms.
- **Python Requests Library**: Automates tests for enumeration, rate limiting, or injection.

### **Tool Setup Instructions**

1. **Burp Suite Community Edition**:
   - Download from [PortSwigger](https://portswigger.net/burp/communitydownload).
   - Configure browser proxy: 127.0.0.1:8080 (Firefox recommended).
   - Enable “Intercept” in Proxy tab.
   - Verify: `curl -x http://127.0.0.1:8080 http://example.com`.
2. **Postman**:
   - Download from [postman.com](https://www.postman.com/downloads/).
   - Install and create a free account.
   - Verify: Open Postman and check version.
3. **cURL**:
   - Install on Linux: `sudo apt install curl`.
   - Install on Windows/Mac: Pre-installed or download from [curl.se](https://curl.se/).
   - Verify: `curl --version`.
4. **Browser Developer Tools**:
   - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
   - No setup required.
5. **Python Requests Library**:
   - Install Python: `sudo apt install python3`.
   - Install Requests: `pip install requests`.
   - Verify: `python3 -c "import requests; print(requests.__version__)"`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-IDNT-02, focusing on testing input validation, role assignments, password policies, verification mechanisms, and anti-automation controls in the user registration process.

### **1. Test Input Validation with Burp Suite**

Submit valid and invalid registration data to identify vulnerabilities in input handling.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com/register` to the target scope in the “Target” tab.
2. **Capture Registration Request**:
   - Fill out the registration form (e.g., username, email, password) and submit.
   - Check “HTTP History” for the POST request to `/register`.
3. **Test Invalid Inputs**:
   - Modify fields with malicious inputs (e.g., SQL injection: `email=' OR '1'='1`, XSS: `username=<script>alert(1)</script>`).
   - Submit empty, oversized, or special character inputs (e.g., `password=😈`).
4. **Analyze Responses**:
   - Look for errors exposing system details (e.g., SQL errors) or accepting invalid inputs.
   - Expected secure response: Generic errors (e.g., “Invalid input”).
5. **Document Findings**:
   - Save requests and responses in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Test SQL injection in email field:
  ```
  HTTP History -> Select POST /register -> Send to Repeater -> Change email=user@example.com to email=' OR '1'='1 -> Click Send -> Check response
  ```
- **Command 2**: Test weak password:
  ```
  HTTP History -> Select POST /register -> Send to Repeater -> Change password=SecurePass123 to password=123 -> Click Send -> Check if accepted
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 500 Internal Server Error
Content-Type: text/html
SQL Error: You have an error in your SQL syntax...
```

**Remediation**:
- Sanitize inputs and use parameterized queries:
  ```python
  from flask import Flask, request
  import sqlite3
  app = Flask(__name__)
  @app.post('/register')
  def register():
      email = request.form['email']
      conn = sqlite3.connect('users.db')
      conn.execute('INSERT INTO users (email) VALUES (?)', (email,))
      conn.commit()
      return jsonify({'status': 'success'})
  ```

### **2. Test Role Assignment with Postman**

Verify that the registration process assigns appropriate roles and prevents privilege escalation.

**Steps**:
1. **Identify Registration Endpoint**:
   - Use Burp Suite to find the registration API (e.g., `POST /api/register`).
   - Import into Postman.
2. **Test Role Manipulation**:
   - Submit registration requests with role parameters (e.g., `{"role": "admin"}`).
   - Attempt to set hidden fields or undocumented parameters (e.g., `is_admin=true`).
3. **Analyze Responses**:
   - Check if the account is created with elevated privileges (e.g., access to `/admin`).
   - Expected secure response: HTTP 403 or role ignored.
4. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Test role parameter manipulation:
  ```
  New Request -> POST http://example.com/api/register -> Body -> JSON: {"email": "test@example.com", "password": "Secure123", "role": "admin"} -> Send
  ```
- **Command 2**: Test hidden admin flag:
  ```
  New Request -> POST http://example.com/api/register -> Body -> JSON: {"email": "test@example.com", "password": "Secure123", "is_admin": true} -> Send
  ```

**Example Vulnerable Response**:
```json
{
  "status": "success",
  "role": "admin"
}
```

**Remediation**:
- Enforce default user role server-side:
  ```javascript
  app.post('/api/register', (req, res) => {
      const { email, password } = req.body;
      if (req.body.role || req.body.is_admin) {
          return res.status(403).json({ error: 'Invalid parameters' });
      }
      // Register with default role: user
      res.json({ status: 'success', role: 'user' });
  });
  ```

### **3. Test Password Policies with cURL**

Check if the registration process enforces strong password requirements.

**Steps**:
1. **Identify Registration Endpoint**:
   - Use Burp Suite to find `POST /register`.
2. **Submit Weak Passwords**:
   - Test passwords that are short (e.g., `123`), repetitive (e.g., `aaa`), or lack complexity (e.g., `password`).
   - Use cURL to send registration requests.
3. **Analyze Responses**:
   - Check if weak passwords are accepted (HTTP 200) or rejected (e.g., “Password too weak”).
   - Expected secure response: Rejection of weak passwords.
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Test short password:
  ```bash
  curl -i -X POST -d "email=test@example.com&password=123" http://example.com/register
  ```
- **Command 2**: Test repetitive password:
  ```bash
  curl -i -X POST -d "email=test@example.com&password=aaaaaa" http://example.com/register
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Account created"}
```

**Remediation**:
- Enforce strong password policies:
  ```javascript
  app.post('/register', (req, res) => {
      const password = req.body.password;
      if (!/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{8,}$/.test(password)) {
          return res.status(400).json({ error: 'Password must be 8+ characters with uppercase, lowercase, and numbers' });
      }
      // Register user
  });
  ```

### **4. Test Enumeration with Browser Developer Tools**

Analyze error messages during registration to detect account enumeration risks.

**Steps**:
1. **Open Browser Developer Tools**:
   - Load `https://example.com/register` and press `F12` in Chrome/Firefox.
2. **Submit Registration Data**:
   - Register with an existing email or username.
   - Check “Network” tab for the POST response.
3. **Analyze Error Messages**:
   - Look for messages like “Email already exists” vs. “Invalid input.”
   - Test multiple emails to confirm enumeration (e.g., `admin@example.com`, `test@example.com`).
4. **Document Findings**:
   - Save screenshots and network logs.

**Browser Developer Tools Commands**:
- **Command 1**: Check registration response:
  ```
  Network tab -> Select POST /register -> Response tab -> Look for "Email already registered"
  ```
- **Command 2**: Test multiple emails:
  ```
  Network tab -> Submit form with email=admin@example.com -> Check response -> Repeat with email=test@example.com
  ```

**Example Vulnerable Response**:
```json
{
  "error": "Email already registered"
}
```

**Remediation**:
- Use generic error messages:
  ```python
  @app.post('/register')
  def register():
      email = request.form['email']
      if db.users.find_one({'email': email}):
          return jsonify({'error': 'Registration failed'}), 400
      return jsonify({'status': 'success'})
  ```

### **5. Test Anti-Automation with Python Requests**

Attempt automated registrations to verify rate limiting, CAPTCHAs, or email verification.

**Steps**:
1. **Write Python Script**:
   - Create a script to send multiple registration requests:
     ```python
     import requests
     import time

     url = 'http://example.com/register'
     for i in range(5):
         data = {
             'email': f'test{i}@example.com',
             'password': 'Secure123',
             'username': f'testuser{i}'
         }
         response = requests.post(url, data=data)
         print(f"Attempt {i+1}: Status={response.status_code}, Response={response.text[:100]}")
         if 'CAPTCHA required' in response.text or response.status_code == 429:
             print("Anti-automation detected")
             break
         time.sleep(1)
     ```
2. **Run Script**:
   - Execute: `python3 test_registration.py`.
   - Analyze responses for rate limits (HTTP 429) or CAPTCHA prompts.
3. **Verify Findings**:
   - Check if accounts are created without verification.
   - Expected secure response: Rate limiting or CAPTCHA enforced.
4. **Document Results**:
   - Save script output.

**Python Commands**:
- **Command 1**: Run registration test:
  ```bash
  python3 test_registration.py
  ```
- **Command 2**: Test single registration:
  ```bash
  python3 -c "import requests; r=requests.post('http://example.com/register', data={'email': 'test@example.com', 'password': '123'}); print(r.status_code, r.text[:100])"
  ```

**Example Vulnerable Output**:
```
Attempt 1: Status=200, Response={"status": "Account created"}
Attempt 2: Status=200, Response={"status": "Account created"}
```

**Remediation**:
- Implement rate limiting and CAPTCHA:
  ```javascript
  const rateLimit = require('express-rate-limit');
  app.use('/register', rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5 // 5 requests
  }));
  app.post('/register', (req, res) => {
      if (!req.body.captcha) {
          return res.status(400).json({ error: 'CAPTCHA required' });
      }
      // Register user
  });
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-IDNT-02 with practical scenarios based on common user registration vulnerabilities observed in penetration testing.

### **Test 1: Weak Password Policy**

**Objective**: Verify if weak passwords are rejected during registration.

**Steps**:
1. **Submit Weak Password**:
   - Use Burp Suite to intercept `POST /register`.
   - Command:
     ```
     HTTP History -> Select POST /register -> Send to Repeater -> Change password=Secure123 to password=123 -> Click Send
     ```
2. **Analyze Response**:
   - Check if the password is accepted (HTTP 200).
   - Expected secure response: HTTP 400 with “Password too weak.”
3. **Verify with cURL**:
   - Command:
     ```bash
     curl -i -X POST -d "email=test@example.com&password=123" http://example.com/register
     ```
4. **Save Results**:
   - Save Burp Suite and cURL outputs.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: application/json
{"status": "Account created"}
```

**Remediation**:
```python
@app.post('/register')
def register():
    password = request.form['password']
    if len(password) < 8 or not any(c.isupper() for c in password):
        return jsonify({'error': 'Password too weak'}), 400
    return jsonify({'status': 'success'})
```

### **Test 2: Role Manipulation**

**Objective**: Test if a user can register with elevated privileges.

**Steps**:
1. **Capture Request**:
   - Use Burp Suite to intercept `POST /api/register`.
   - Command:
     ```
     HTTP History -> Select POST /api/register -> Send to Repeater
     ```
2. **Modify Role**:
   - Command:
     ```
     Repeater -> Change JSON: {"email": "test@example.com", "password": "Secure123"} to {"email": "test@example.com", "password": "Secure123", "role": "admin"} -> Click Send
     ```
3. **Analyze Response**:
   - Check if the account has admin privileges (e.g., access `/admin`).
   - Expected secure response: HTTP 403 or role ignored.
4. **Save Results**:
   - Save Burp Suite outputs.

**Example Vulnerable Response**:
```json
{
  "status": "success",
  "role": "admin"
}
```

**Remediation**:
```javascript
app.post('/api/register', (req, res) => {
    delete req.body.role; // Ignore client-supplied role
    // Assign default role: user
    res.json({ status: 'success', role: 'user' });
});
```

### **Test 3: Account Enumeration**

**Objective**: Detect enumeration risks through registration error messages.

**Steps**:
1. **Submit Existing Email**:
   - Use Browser Developer Tools to submit `email=admin@example.com`.
   - Command:
     ```
     Network tab -> Select POST /register -> Response tab -> Look for "Email already registered"
     ```
2. **Test Variations**:
   - Try `email=test@example.com` and compare responses.
   - Command:
     ```
     Network tab -> Submit form with email=test@example.com -> Check response
     ```
3. **Analyze Responses**:
   - Check for distinct messages (e.g., “Email exists” vs. “Invalid input”).
   - Expected secure response: Generic error.
4. **Save Results**:
   - Save screenshots.

**Example Vulnerable Response**:
```json
{
  "error": "Email already registered"
}
```

**Remediation**:
```php
if ($db->query("SELECT * FROM users WHERE email = ?", [$email])->num_rows > 0) {
    return json_encode(['error' => 'Registration failed']);
}
```

### **Test 4: Automated Registration**

**Objective**: Test for rate limiting or CAPTCHA enforcement.

**Steps**:
1. **Run Python Script**:
   - Command:
     ```bash
     python3 test_registration.py
     ```
2. **Analyze Output**:
   - Check for HTTP 429 (Too Many Requests) or CAPTCHA prompts.
   - Expected secure response: Registration blocked after a few attempts.
3. **Verify Manually**:
   - Use Postman to send multiple requests:
     ```
     New Request -> POST http://example.com/register -> Body -> Form-data: email=test{i}@example.com, password=Secure123 -> Send 5 times
     ```
4. **Save Results**:
   - Save script and Postman outputs.

**Example Vulnerable Output**:
```
Attempt 5: Status=200, Response={"status": "Account created"}
```

**Remediation**:
```python
from flask_limiter import Limiter
limiter = Limiter(app, key_func=lambda: request.remote_addr)
@app.route('/register', methods=['POST'])
@limiter.limit('5 per day')
def register():
    return jsonify({'status': 'success'})
```

## **Additional Tips**

- **Test All Fields**: Submit malicious inputs to all registration fields (e.g., username, email, phone).
- **Combine Tools**: Use Burp Suite for manual testing, Postman for APIs, and Python for automation.
- **Gray-Box Testing**: If documentation is available, verify password policies, role defaults, or CAPTCHA configurations.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Ethical Considerations**: Obtain explicit permission for testing, as automated registration or injection attempts may disrupt live systems or violate terms of service.
- **References**: [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html).