# **Test Ability to Forge Requests**

## **Overview**

Testing the ability to forge requests (WSTG-BUSL-02) involves assessing whether a web application allows attackers to craft or manipulate HTTP requests to bypass business logic or access unauthorized functionality. Forged requests exploit weak validation or improper session management, enabling actions like accessing another user’s data, performing privileged operations, or skipping workflow steps. According to OWASP, these vulnerabilities are context-specific and often require manual testing to identify, as automated tools may miss subtle logic flaws.

**Impact**: The ability to forge requests can lead to:
- Unauthorized access to restricted resources (e.g., admin panels, user accounts).
- Bypassing critical business logic (e.g., skipping payment verification).
- Data integrity violations (e.g., modifying another user’s profile).
- Financial or operational damage due to unauthorized actions.

This guide provides a step-by-step methodology for testing the ability to forge requests, adhering to OWASP’s WSTG-BUSL-02, with practical tools, real-world test cases, and remediation strategies for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing the ability to forge requests, suitable for both novice and experienced testers:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to forge custom requests.
- **OWASP ZAP**: Open-source web proxy for analyzing and modifying requests.
- **cURL**: Command-line tool for crafting and sending custom HTTP requests.
- **Postman**: Tool for testing and forging API requests.
- **Browser Developer Tools**: Built-in browser tools (Chrome/Firefox) for inspecting and modifying requests.
- **FoxyProxy**: Browser extension to route traffic through Burp Suite or OWASP ZAP.
- **Charles Proxy**: Proxy tool for analyzing and forging mobile or web traffic.
- **Python Requests Library**: Python library for scripting custom HTTP requests.
- **Tamper Data**: Browser extension for intercepting and modifying requests (Firefox).
- **Repeater (Burp Suite)**: Built-in Burp Suite tool for replaying and modifying requests.

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
7. **Charles Proxy**:
   - Download from [charlesproxy.com](https://www.charlesproxy.com/).
   - Configure proxy: 127.0.0.1:8888.
   - Verify: Start proxy and check traffic.
8. **Python Requests Library**:
   - Install Python: `sudo apt install python3`.
   - Install Requests: `pip install requests`.
   - Verify: `python3 -c "import requests; print(requests.__version__)"`.
9. **Tamper Data**:
   - Install on Firefox from add-ons store.
   - Enable and verify request interception.
10. **Repeater (Burp Suite)**:
    - Included in Burp Suite; access via “Repeater” tab.
    - No additional setup required.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-BUSL-02, focusing on crafting and sending forged requests to bypass business logic or access unauthorized functionality.

### **1. Capture and Analyze Requests with Burp Suite**

Identify requests that control business logic or access sensitive functionality.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Interact with the Application**:
   - Perform actions like logging in, accessing user profiles, or submitting forms.
   - Capture requests in Burp Suite’s “HTTP History”.
3. **Analyze Requests**:
   - Identify requests with sensitive actions (e.g., `POST /profile/update`, `GET /admin`).
   - Note parameters, cookies, headers, or tokens (e.g., `session_id`, `user_id`).
4. **Document Findings**:
   - Save requests in Burp Suite’s “Logger” or a text file.

**Example Request**:
```
GET /profile?user_id=123 HTTP/1.1
Host: example.com
Cookie: session_id=abc123
```

**Remediation**:
- Validate session ownership server-side:
  ```php
  if ($_GET['user_id'] != $_SESSION['user_id']) {
      http_response_code(403);
      exit('Unauthorized');
  }
  ```
- Use secure session management.

### **2. Forge Requests with Burp Suite Repeater**

Craft and send modified requests to test for unauthorized access or logic bypass.

**Steps**:
1. **Send to Repeater**:
   - Right-click a request in “HTTP History” and select “Send to Repeater”.
   - Modify parameters (e.g., change `user_id=123` to `user_id=456`).
   - Send the forged request.
2. **Test Scenarios**:
   - Change user IDs to access other accounts (e.g., `user_id=admin`).
   - Alter roles or permissions (e.g., `role=user` to `role=admin`).
   - Replay requests out of sequence (e.g., skip authentication).
3. **Analyze Response**:
   - Check if the application processes the forged request (e.g., returns another user’s data).
   - Look for errors or unauthorized access.
4. **Document Findings**:
   - Save forged requests and responses.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html

User Profile: admin@example.com
```

**Remediation**:
- Implement proper authorization checks:
  ```javascript
  if (!req.session.isAdmin && req.query.role === 'admin') {
      res.status(403).send('Access denied');
  }
  ```
- Log unauthorized request attempts.

### **3. Forge API Requests with Postman**

Test API endpoints for vulnerabilities to forged requests.

**Steps**:
1. **Identify API Endpoints**:
   - Use Burp Suite to find APIs (e.g., `/api/v1/users`).
   - Import endpoints into Postman.
2. **Craft Forged Requests**:
   - Send requests with modified parameters (e.g., `GET /api/v1/users/456` instead of `/api/v1/users/123`).
   - Test unauthorized methods (e.g., `DELETE /api/v1/users/456`).
3. **Analyze Response**:
   - Check if the API returns unauthorized data or performs actions.
   - Look for verbose error messages.
4. **Document Findings**:
   - Save API requests and responses in Postman.

**Example Vulnerable API Response**:
```json
{
  "user_id": 456,
  "email": "otheruser@example.com"
}
```

**Remediation**:
- Enforce API authentication:
  ```python
  if not verify_token(request.headers.get('Authorization')):
      return jsonify({'error': 'Unauthorized'}), 403
  ```
- Validate resource ownership.

### **4. Modify Client-Side Requests with Browser Developer Tools**

Test whether client-side request modifications bypass server-side logic.

**Steps**:
1. **Open Developer Tools**:
   - Press `F12` on `http://example.com/profile` and go to “Network” tab.
   - Perform an action (e.g., submit a form) and capture the request.
2. **Modify Request**:
   - Use Tamper Data or Charles Proxy to intercept and alter the request (e.g., change `user_id=123` to `user_id=456`).
   - Send the modified request.
3. **Analyze Response**:
   - Check if the server processes the forged request (e.g., displays another user’s profile).
   - Note any errors or redirects.
4. **Document Findings**:
   - Save screenshots and server responses.

**Example Vulnerable Finding**:
- Modified: `user_id=456`
- Response: Profile data for `otheruser@example.com`.

**Remediation**:
- Avoid relying on client-side parameters:
  ```php
  $user_id = $_SESSION['user_id']; // Use session data, not GET/POST
  ```
- Implement CSRF tokens for forms.

### **5. Automate Forged Requests with Python Requests**

Script automated tests to forge multiple request variations.

**Steps**:
1. **Write Python Script**:
   - Create a script to test forged user IDs:
     ```python
     import requests

     url = 'http://example.com/profile'
     cookies = {'session_id': 'abc123'}
     user_ids = [123, 456, 'admin', 999999]

     for user_id in user_ids:
         params = {'user_id': user_id}
         response = requests.get(url, cookies=cookies, params=params)
         print(f"User ID: {user_id}")
         print(f"Response: {response.text}\n")
     ```
2. **Run Script**:
   - Execute: `python3 test.py`.
   - Analyze responses for unauthorized access.
3. **Verify Findings**:
   - Cross-check with Burp Suite results.
4. **Document Results**:
   - Save script output and responses.

**Example Vulnerable Output**:
```
User ID: 456
Response: User Profile: otheruser@example.com
```

**Remediation**:
- Validate user permissions:
  ```javascript
  if (req.query.user_id !== req.session.user_id) {
      res.status(403).send('Unauthorized');
  }
  ```
- Rate-limit requests to prevent automation.

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-BUSL-02 with practical scenarios based on common request forgery vulnerabilities observed in penetration testing.

### **Test 1: Access Another User’s Profile**

Test whether forging a user ID grants access to another user’s profile.

**Steps**:
1. **Capture Request**:
   - Use Burp Suite to capture:
     ```
     GET /profile?user_id=123 HTTP/1.1
     Host: example.com
     Cookie: session_id=abc123
     ```
2. **Forge Request**:
   - In Repeater, change `user_id=123` to `user_id=456`.
   - Send request.
3. **Verify**:
   - Check if profile data for user 456 is returned.

**Example Insecure Finding**:
- Response: `User Profile: otheruser@example.com`

**Example Secure Configuration**:
- Validate user ID:
  ```php
  if ($_GET['user_id'] != $_SESSION['user_id']) {
      header('HTTP/1.1 403 Forbidden');
      exit;
  }
  ```

**Remediation**:
- Tie requests to authenticated sessions.
- Log unauthorized access attempts.

### **Test 2: Bypassing Admin Access Controls**

Test whether forging a role parameter grants admin access.

**Steps**:
1. **Capture Request**:
   - Use OWASP ZAP to capture:
     ```
     GET /dashboard?role=user HTTP/1.1
     Host: example.com
     Cookie: session_id=abc123
     ```
2. **Forge Request**:
   - Change `role=user` to `role=admin`.
   - Send request.
3. **Verify**:
   - Check if admin dashboard is accessible.

**Example Insecure Finding**:
- Response: Admin dashboard with sensitive controls.

**Example Secure Configuration**:
- Validate roles server-side:
  ```javascript
  if (req.query.role === 'admin' && !req.session.isAdmin) {
      res.status(403).send('Access denied');
  }
  ```

**Remediation**:
- Store roles in server-side sessions.
- Use role-based access control (RBAC).

### **Test 3: Forging API Delete Request**

Test whether an unauthorized API delete request is processed.

**Steps**:
1. **Capture API Request**:
   - In Postman, send:
     ```json
     DELETE /api/v1/users/123 HTTP/1.1
     Host: example.com
     Authorization: Bearer abc123
     ```
2. **Forge Request**:
   - Change to `DELETE /api/v1/users/456`.
   - Send request.
3. **Verify**:
   - Check if user 456 is deleted.

**Example Insecure Finding**:
- Response: `{"status": "User deleted"}`

**Example Secure Configuration**:
- Validate ownership:
  ```python
  if request.user.id != int(user_id):
      return jsonify({'error': 'Unauthorized'}), 403
  ```

**Remediation**:
- Require strong authentication for destructive actions.
- Implement audit logging.

### **Test 4: Skipping Workflow Steps**

Test whether forging a request skips a required workflow step (e.g., payment).

**Steps**:
1. **Capture Request**:
   - Use Charles Proxy to capture:
     ```
     POST /order/confirm HTTP/1.1
     Host: example.com
     Cookie: session_id=abc123
     order_id=789
     ```
2. **Forge Request**:
   - Send request without prior `POST /payment`.
   - Check response.
3. **Verify**:
   - Check if order is confirmed without payment.

**Example Insecure Finding**:
- Response: `Order Confirmed`

**Example Secure Configuration**:
- Validate workflow state:
  ```php
  if (!isset($_SESSION['payment_completed'])) {
      header('Location: /payment');
      exit;
  }
  ```

**Remediation**:
- Enforce workflow state checks.
- Use transaction IDs to track steps.

## **Additional Tips**

- **Understand Application Logic**: Study the application’s workflows (e.g., user roles, order processes) to identify forgeable requests.
- **Combine Tools**: Use Burp Suite for initial capture, Postman for APIs, and Python for automation.
- **Gray-Box Testing**: If documentation is available, check for session or permission logic.
- **Document Thoroughly**: Save all forged requests, responses, and screenshots in a report.
- **Bypass Defenses**: Test edge cases (e.g., invalid tokens, missing headers) to uncover weak validation.
- **Stay Ethical**: Obtain explicit permission for active testing and avoid disrupting live systems.
- **Follow Best Practices**: Refer to OWASP’s Business Logic Testing section for additional techniques: [OWASP WSTG Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/).