# **Testing for the Circumvention of Work Flows**

## **Overview**

Testing for the circumvention of workflows (WSTG-BUSL-06) involves assessing whether a web application enforces the intended sequence of steps in its business processes, preventing attackers from bypassing critical stages, such as payment or authentication, to achieve unauthorized outcomes. According to OWASP, workflow vulnerabilities arise when applications rely on client-side controls or fail to validate the state of a process server-side, allowing attackers to skip or manipulate steps (e.g., accessing a checkout page without payment). This test focuses on identifying weaknesses that permit workflow circumvention, which can undermine the application's business logic.

**Impact**: Workflow circumvention can lead to:
- Financial fraud (e.g., obtaining goods without payment).
- Unauthorized access (e.g., bypassing approval steps).
- Data integrity violations (e.g., modifying records without validation).
- Operational disruptions due to exploited process flaws.

This guide provides a step-by-step methodology for testing workflow circumvention, adhering to OWASP’s WSTG-BUSL-06, with practical tools, at least two specific commands or configurations per tool for real security testing, real-world test cases, remediation strategies, and ethical considerations for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing workflow circumvention, with at least two specific commands or configurations provided for each to enable real security testing:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to bypass workflow steps.
- **cURL**: Command-line tool for crafting requests to access out-of-sequence endpoints.
- **Postman**: Tool for testing API workflows and skipping steps.
- **Browser Developer Tools**: Built-in browser tools (Chrome/Firefox) for inspecting and manipulating workflow requests.
- **Python Requests Library**: Python library for scripting requests to test workflow bypasses.

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
4. **Browser Developer Tools**:
   - Access in Chrome/Firefox: Press `F12` or right-click and select “Inspect”.
   - No setup required.
5. **Python Requests Library**:
   - Install Python: `sudo apt install python3`.
   - Install Requests: `pip install requests`.
   - Verify: `python3 -c "import requests; print(requests.__version__)"`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-BUSL-06, focusing on attempting to bypass or manipulate workflow steps to access unauthorized functionality or achieve unintended outcomes.

### **1. Map Workflows with Burp Suite**

Identify the intended sequence of steps in critical workflows, such as checkout or user registration.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Interact with the Application**:
   - Perform actions like placing an order or registering a user.
   - Capture requests in Burp Suite’s “HTTP History”.
3. **Map Workflow**:
   - Identify sequential endpoints (e.g., `/cart`, `/payment`, `/confirm`).
   - Note parameters, session tokens, or state indicators (e.g., `order_id`, `step`).
4. **Document Findings**:
   - Save workflow requests in Burp Suite’s “Logger”.

**Burp Suite Commands**:
- **Command 1**: Capture and analyze a checkout workflow to identify steps:
  ```
  Proxy tab -> HTTP History -> Filter by example.com -> Select requests (e.g., POST /cart, POST /payment, POST /confirm) -> Right-click -> Add to Site Map -> Target tab -> Site Map -> Review request sequence
  ```
- **Command 2**: Use Repeater to skip the payment step by sending the confirm request directly:
  ```
  Right-click POST /confirm in HTTP History -> Send to Repeater -> Ensure order_id=123 and session=abc123 -> Click "Send" -> Check response in "Response" pane
  ```

**Example Workflow**:
```
POST /cart HTTP/1.1
Host: example.com
item_id=456&quantity=1

POST /payment HTTP/1.1
Host: example.com
order_id=123&amount=99.99

POST /confirm HTTP/1.1
Host: example.com
order_id=123
```

**Remediation**:
- Validate workflow state server-side:
  ```php
  session_start();
  if (!isset($_SESSION['payment_completed']) || $_SESSION['order_id'] !== $_POST['order_id']) {
      die('Invalid workflow state');
  }
  ```

### **2. Bypass Steps with cURL**

Attempt to access workflow endpoints out of sequence to test for circumvention.

**Steps**:
1. **Identify Endpoints**:
   - Use Burp Suite to note workflow URLs (e.g., `/confirm`).
2. **Craft Out-of-Sequence Requests**:
   - Use cURL to send requests directly to later steps.
   - Include valid session cookies or tokens.
3. **Analyze Response**:
   - Check if the application processes the request (e.g., order confirmed without payment).
   - Look for errors or redirects.
4. **Document Findings**:
   - Save cURL commands and responses.

**cURL Commands**:
- **Command 1**: Skip payment and directly confirm an order:
  ```bash
  curl -X POST -d "order_id=123" -b "session=abc123" http://example.com/confirm
  ```
- **Command 2**: Access a user dashboard without completing registration:
  ```bash
  curl -X GET -b "session=abc123" http://example.com/dashboard
  ```

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html
Order Confirmed: Order #123
```

**Remediation**:
- Enforce step validation:
  ```javascript
  if (!req.session.payment_verified) {
      res.redirect('/payment');
  }
  ```

### **3. Test API Workflow Bypasses with Postman**

Test API endpoints for workflow circumvention vulnerabilities.

**Steps**:
1. **Identify API Workflow**:
   - Use Burp Suite to find APIs (e.g., `/api/v1/order/confirm`).
   - Import into Postman.
2. **Skip Steps**:
   - Send requests to later endpoints without completing prior steps.
   - Use valid authentication tokens.
3. **Analyze Response**:
   - Check if the API processes out-of-sequence requests.
   - Look for error codes or unintended success.
4. **Document Findings**:
   - Save Postman requests and responses.

**Postman Commands**:
- **Command 1**: Send a direct order confirmation request:
  ```
  New Request -> POST http://example.com/api/v1/order/confirm -> Body: {"order_id": 123} -> Headers: Cookie: session=abc123 -> Send
  ```
- **Command 2**: Access a protected API endpoint without prior steps:
  ```
  New Request -> GET http://example.com/api/v1/user/profile -> Headers: Authorization: Bearer xyz789 -> Send
  ```

**Example Vulnerable API Response**:
```json
{
  "status": "success",
  "message": "Order #123 confirmed"
}
```

**Remediation**:
- Validate API workflow state:
  ```python
  if not session.get('payment_completed'):
      return jsonify({'error': 'Payment required'}), 403
  ```

### **4. Manipulate Client-Side Workflow with Browser Developer Tools**

Test whether client-side controls can be bypassed to skip workflow steps.

**Steps**:
1. **Inspect Workflow**:
   - Open Developer Tools (`F12`) on a workflow page (e.g., `http://example.com/payment`).
   - Identify redirects or JavaScript controlling navigation (e.g., `window.location`).
2. **Manipulate Requests**:
   - Modify form actions or URLs to point to later steps.
   - Disable JavaScript to bypass client-side redirects.
3. **Analyze Response**:
   - Check if the server accepts the request.
   - Note any errors or unauthorized access.
4. **Document Findings**:
   - Save screenshots and responses.

**Browser Developer Tools Commands**:
- **Command 1**: Change a form’s action to skip payment:
  ```
  Elements tab -> Find <form action="/payment"> -> Right-click -> Edit as HTML -> Change to action="/confirm" -> Submit form
  ```
- **Command 2**: Disable JavaScript to bypass client-side workflow checks:
  ```
  Chrome: Settings -> Privacy and Security -> Site Settings -> JavaScript -> Don’t allow sites to use JavaScript -> Refresh page -> Navigate to http://example.com/confirm
  ```

**Example Vulnerable Finding**:
- Modified form action -> Response: `Order Confirmed`.

**Remediation**:
- Avoid client-side workflow logic:
  ```php
  if ($_SERVER['REQUEST_URI'] === '/confirm' && !$_SESSION['payment_completed']) {
      header('Location: /payment');
      exit;
  }
  ```

### **5. Script Workflow Bypasses with Python Requests**

Automate tests to bypass workflow steps and evaluate server-side validation.

**Steps**:
1. **Write Python Script**:
   - Create a script to access a later workflow step directly:
     ```python
     import requests

     url = 'http://example.com/confirm'
     data = {'order_id': '123'}
     cookies = {'session': 'abc123'}
     headers = {'User-Agent': 'Mozilla/5.0'}

     # Attempt to skip payment
     response = requests.post(url, data=data, cookies=cookies, headers=headers)
     print(f"Status: {response.status_code}")
     print(f"Response: {response.text}")

     # Attempt to access dashboard without registration
     dashboard_url = 'http://example.com/dashboard'
     response = requests.get(dashboard_url, cookies=cookies, headers=headers)
     print(f"Dashboard Status: {response.status_code}")
     print(f"Dashboard Response: {response.text}")
     ```
2. **Run Script**:
   - Execute: `python3 test.py`.
   - Analyze responses for unauthorized access.
3. **Verify Findings**:
   - Cross-check with Burp Suite results.
4. **Document Results**:
   - Save script output and responses.

**Python Commands**:
- **Command 1**: Run the above script to test order confirmation bypass:
  ```bash
  python3 test.py
  ```
- **Command 2**: Modify the script to test profile access without prior steps and run:
  ```python
  import requests
  url = 'http://example.com/api/v1/user/profile'
  cookies = {'session': 'abc123'}
  response = requests.get(url, cookies=cookies)
  print(f"Status: {response.status_code}")
  print(f"Response: {response.text}")
  ```
  ```bash
  python3 test_profile.py
  ```

**Example Vulnerable Output**:
```
Status: 200
Response: {"status": "success", "message": "Order #123 confirmed"}
Dashboard Status: 200
Dashboard Response: Welcome to your dashboard
```

**Remediation**:
- Track workflow state:
  ```javascript
  if (!req.session.workflow_step || req.session.workflow_step !== 'payment_completed') {
      res.status(403).send('Invalid workflow state');
  }
  ```

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-BUSL-06 with practical scenarios based on common workflow circumvention vulnerabilities observed in penetration testing.

### **Test 1: Skip Payment in E-commerce Checkout**

Test whether an order can be confirmed without completing payment.

**Steps**:
1. **Capture Workflow**:
   - Use Burp Suite to capture: `POST /cart`, `POST /payment`, `POST /confirm`.
2. **Skip Payment**:
   - Use cURL: `curl -X POST -d "order_id=123" -b "session=abc123" http://example.com/confirm`.
3. **Verify**:
   - Check if order is confirmed.

**Example Insecure Finding**:
- Response: `Order Confirmed: #123`.

**Example Secure Configuration**:
- Validate payment:
  ```php
  if (!DB::exists('SELECT 1 FROM payments WHERE order_id = ?', [$_POST['order_id']])) {
      die('Payment required');
  }
  ```

**Remediation**:
- Store workflow state in session.
- Validate each step server-side.

### **Test 2: Access Dashboard Without Registration**

Test whether a user can access a dashboard without completing registration.

**Steps**:
1. **Capture Request**:
   - Use Postman to send: `GET /dashboard`.
2. **Send Direct Request**:
   - Use Postman command: `GET http://example.com/dashboard` with `Cookie: session=abc123`.
3. **Verify**:
   - Check if dashboard is accessible.

**Example Insecure Finding**:
- Response: `Welcome to your dashboard`.

**Example Secure Configuration**:
- Check registration status:
  ```javascript
  if (!req.session.user.registered) {
      res.redirect('/register');
  }
  ```

**Remediation**:
- Enforce registration checks.
- Use secure session management.

### **Test 3: Bypass Approval Workflow**

Test whether an approval step can be skipped in a request workflow.

**Steps**:
1. **Capture Workflow**:
   - Use Burp Suite to capture: `POST /request`, `POST /approve`.
2. **Send Approval Directly**:
   - Use Python script command: `python3 test.py`.
3. **Verify**:
   - Check if request is approved.

**Example Insecure Finding**:
- Response: `Request #789 approved`.

**Example Secure Configuration**:
- Validate state:
  ```python
  request = db.query("SELECT status FROM requests WHERE id = ?", [request_id]).fetchone()
  if request.status != "pending":
      return jsonify({"error": "Invalid state"}), 403
  ```

**Remediation**:
- Track request states in database.
- Log unauthorized attempts.

### **Test 4: Manipulate Client-Side Redirect**

Test whether disabling client-side redirects allows workflow bypass.

**Steps**:
1. **Inspect Page**:
   - Use Browser Developer Tools to disable JavaScript.
2. **Navigate Directly**:
   - Use command: Disable JavaScript and access `http://example.com/confirm`.
3. **Verify**:
   - Check if confirmation page is accessible.

**Example Insecure Finding**:
- Response: `Order Confirmed`.

**Example Secure Configuration**:
- Server-side redirect:
  ```php
  if (!isset($_SESSION['cart_completed'])) {
      header('Location: /cart');
      exit;
  }
  ```

**Remediation**:
- Avoid client-side redirects.
- Implement server-side state checks.

## **Additional Tips**

- **Map Workflows Thoroughly**: Document all steps in critical processes (e.g., checkout, registration) to identify bypass opportunities.
- **Combine Tools**: Use Burp Suite for mapping, cURL for quick tests, and Python for automation.
- **Gray-Box Testing**: If documentation is available, check for state management or session logic.
- **Document Thoroughly**: Save all commands, responses, and screenshots in a report.
- **Bypass Defenses**: Test with manipulated tokens or missing parameters to uncover weak validation.
- **Stay Ethical**: Obtain explicit permission for active testing and avoid disrupting live systems.
- **Follow Best Practices**: Refer to OWASP’s Business Logic Testing section for additional techniques: [OWASP WSTG Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/).