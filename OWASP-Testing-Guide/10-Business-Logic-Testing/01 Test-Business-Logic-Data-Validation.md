# **Test Business Logic Data Validation**

## **Overview**

Testing business logic data validation (WSTG-BUSL-01) involves assessing whether a web application properly validates user inputs and data within its business logic to prevent manipulation, bypass, or exploitation. Business logic flaws occur when an application fails to enforce rules or constraints specific to its functionality, allowing attackers to submit unexpected or malicious data to achieve unauthorized actions (e.g., altering prices, bypassing restrictions). According to OWASP, these vulnerabilities are often missed by automated scanners and require manual testing to identify context-specific issues.[](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/00-Introduction_to_Business_Logic)

**Impact**: Weak business logic data validation can lead to:
- Unauthorized actions (e.g., purchasing items at manipulated prices).
- Bypassing restrictions (e.g., negative quantities in e-commerce carts).
- Data integrity violations (e.g., tampering with account balances).
- Financial loss or reputational damage due to exploited workflows.

This guide provides a step-by-step methodology for testing business logic data validation, adhering to OWASP’s WSTG-BUSL-01, with practical tools, real-world test cases, and remediation strategies for professional penetration testing.

## **Testing Tools**

The following tools are recommended for testing business logic data validation, suitable for both novice and experienced testers:

- **Burp Suite Community Edition**: Intercepts and manipulates HTTP requests to test input validation.
- **OWASP ZAP**: Open-source web proxy for analyzing and modifying requests.
- **cURL**: Command-line tool for crafting and sending custom HTTP requests.
- **Postman**: Tool for testing API endpoints and manipulating parameters.
- **Browser Developer Tools**: Built-in browser tools (Chrome/Firefox) for inspecting and modifying form data.
- **FoxyProxy**: Browser extension to route traffic through Burp Suite or OWASP ZAP.
- **Web Developer Toolbar**: Browser extension for manipulating form inputs and headers.
- **Tamper Data**: Browser extension for intercepting and modifying requests (Firefox).
- **Charles Proxy**: Proxy tool for analyzing and modifying mobile or web traffic.
- **Python Requests Library**: Python library for scripting custom HTTP requests.

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
7. **Web Developer Toolbar**:
   - Install as a browser extension (Chrome/Firefox) from [webdeveloper.com](https://chrispederick.com/work/web-developer/).
   - Enable and verify toolbar functionality.
8. **Tamper Data**:
   - Install on Firefox from add-ons store.
   - Enable and verify request interception.
9. **Charles Proxy**:
   - Download from [charlesproxy.com](https://www.charlesproxy.com/).
   - Configure proxy: 127.0.0.1:8888.
   - Verify: Start proxy and check traffic.
10. **Python Requests Library**:
    - Install Python: `sudo apt install python3`.
    - Install Requests: `pip install requests`.
    - Verify: `python3 -c "import requests; print(requests.__version__)"`.

## **Testing Methodology**

This methodology follows OWASP’s black-box approach for WSTG-BUSL-01, focusing on manipulating inputs and observing application behavior to identify weak data validation in business logic.[](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/00-Introduction_to_Business_Logic)

### **1. Identify Business Logic Inputs with Burp Suite**

Map input points (e.g., forms, API parameters) where business logic validation occurs.

**Steps**:
1. **Configure Burp Suite**:
   - Set up browser proxy (127.0.0.1:8080).
   - Add `example.com` to the target scope in the “Target” tab.
2. **Interact with the Application**:
   - Navigate through the application (e.g., add items to cart, submit forms).
   - Capture requests in Burp Suite’s “HTTP History”.
3. **Identify Input Points**:
   - Look for parameters like `price`, `quantity`, or `discount` in requests (e.g., `POST /cart/add`).
   - Note hidden fields, cookies, or headers influencing logic.
4. **Document Findings**:
   - Save request details (e.g., URLs, parameters) in Burp Suite’s “Logger”.

**Example Request**:
```
POST /cart/add HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

item_id=123&quantity=1&price=99.99
```

**Remediation**:
- Validate inputs server-side:
  ```php
  if (!is_numeric($_POST['quantity']) || $_POST['quantity'] <= 0) {
      die('Invalid quantity');
  }
  ```
- Use whitelists for acceptable values.

### **2. Manipulate Inputs with Burp Suite Repeater**

Test whether the application enforces proper validation by modifying input values.

**Steps**:
1. **Captureme Repeater**:
   - In Burp Suite, right-click a request in “HTTP History” and select “Send to Repeater”.
   - Modify parameters (e.g., change `price=99.99` to `price=-10.00`).
   - Send the modified request and observe the response.
2. **Test Edge Cases**:
   - Submit negative values (e.g., `quantity=-1`).
   - Use large numbers (e.g., `quantity=999999`).
   - Remove or alter critical fields (e.g., omit `item_id`).
3. **Analyze Response**:
   - Check if the application accepts invalid data (e.g., negative price applied).
   - Look for errors or unexpected behavior.
4. **Document Findings**:
   - Save modified requests and responses.

**Example Vulnerable Response**:
```
HTTP/1.1 200 OK
Content-Type: text/html

Order Total: -$10.00
```

**Remediation**:
- Enforce server-side validation:
  ```javascript
  if (req.body.price < 0) {
      res.status(400).send('Invalid price');
  }
  ```
- Log invalid input attempts for monitoring.

### **3. Test API Endpoints with Postman**

Test API endpoints for weak business logic validation.

**Steps**:
1. **Identify API Endpoints**:
   - Use Burp Suite to find APIs (e.g., `/api/v1/cart`).
   - Import endpoints into Postman.
2. **Manipulate Parameters**:
   - Send requests with invalid data (e.g., `PUT /api/v1/cart { "quantity": -5 }`).
   - Test missing or malformed fields.
3. **Analyze Response**:
   - Check if the API processes invalid data (e.g., negative quantities accepted).
   - Look for verbose error messages exposing logic.
4. **Document Findings**:
   - Save API requests and responses in Postman.

**Example Vulnerable API Response**:
```json
{
  "status": "success",
  "total": -50.00
}
```

**Remediation**:
- Validate API inputs:
  ```python
  if request.json.get('quantity', 0) <= 0:
      return jsonify({'error': 'Invalid quantity'}), 400
  ```
- Use schema validation libraries (e.g., Joi, Pydantic).

### **4. Modify Client-Side Inputs with Browser Developer Tools**

Test client-side validation bypasses by modifying form data.

**Steps**:
1. **Open Developer Tools**:
   - Press `F12` on `http://example.com/cart` and go to “Elements” tab.
   - Locate form fields (e.g., `<input name="price" value="99.99">`).
2. **Modify Values**:
   - Change `value="99.99"` to `value="0.01"`.
   - Submit the form.
3. **Analyze Response**:
   - Check if the server accepts the modified value.
   - Look for changes in application state (e.g., cart total).
4. **Document Findings**:
   - Save screenshots and server responses.

**Example Vulnerable Finding**:
- Modified: `<input name="price" value="0.01">`
- Response: Order total updated to $0.01.

**Remediation**:
- Avoid client-side validation alone:
  ```php
  $price = floatval($_POST['price']);
  if ($price <= 0 || $price > 1000) {
      die('Invalid price');
  }
  ```
- Revalidate all inputs server-side.

### **5. Script Automated Tests with Python Requests**

Automate testing of multiple input scenarios for efficiency.

**Steps**:
1. **Write Python Script**:
   - Create a script to test invalid inputs:
     ```python
     import requests

     url = 'http://example.com/cart/add'
     payloads = [
         {'item_id': '123', 'quantity': -1, 'price': 99.99},
         {'item_id': '123', 'quantity': 999999, 'price': 99.99},
         {'item_id': '123', 'quantity': 1, 'price': -10.00}
     ]

     for payload in payloads:
         response = requests.post(url, data=payload)
         print(f"Payload: {payload}")
         print(f"Response: {response.text}\n")
     ```
2. **Run Script**:
   - Execute: `python3 test.py`.
   - Analyze responses for acceptance of invalid data.
3. **Verify Findings**:
   - Cross-check with Burp Suite results.
4. **Document Results**:
   - Save script output and responses.

**Example Vulnerable Output**:
```
Payload: {'item_id': '123', 'quantity': -1, 'price': 99.99}
Response: {"status": "success", "total": -99.99}
```

**Remediation**:
- Implement robust input validation:
  ```javascript
  if (payload.quantity <= 0 || payload.quantity > 100) {
      throw new Error('Invalid quantity');
  }
  ```
- Rate-limit API endpoints to prevent automated abuse.

## **Real-World Test Cases**

These test cases extend OWASP’s WSTG-BUSL-01 with practical scenarios based on common business logic data validation flaws observed in penetration testing.

### **Test 1: Manipulate E-commerce Price**

Test whether an e-commerce application allows price manipulation.

**Steps**:
1. **Capture Request**:
   - Use Burp Suite to capture:
     ```
     POST /cart/add HTTP/1.1
     Host: example.com
     item_id=123&quantity=1&price=99.99
     ```
2. **Modify Price**:
   - In Repeater, change `price=99.99` to `price=0.01`.
   - Send request.
3. **Verify**:
   - Check if cart total reflects $0.01.

**Example Insecure Finding**:
- Response: `Order Total: $0.01`

**Example Secure Configuration**:
- Validate price server-side:
  ```php
  $item = getItem($item_id);
  if ($_POST['price'] != $item['price']) {
      die('Price mismatch');
  }
  ```

**Remediation**:
- Store prices server-side and validate against them.
- Log price manipulation attempts.

### **Test 2: Negative Quantity in Cart**

Test whether the application accepts negative quantities.

**Steps**:
1. **Modify Form**:
   - In Developer Tools, change `<input name="quantity" value="1">` to `value="-10"`.
   - Submit form.
2. **Test with cURL**:
   - Send:
     ```bash
     curl -X POST http://example.com/cart/add -d "item_id=123&quantity=-10&price=99.99"
     ```
3. **Verify**:
   - Check if cart total is negative.

**Example Insecure Finding**:
- Response: `Total: -$999.90`

**Example Secure Configuration**:
- Validate quantity:
  ```javascript
  if (req.body.quantity <= 0) {
      res.status(400).send('Invalid quantity');
  }
  ```

**Remediation**:
- Enforce positive quantities server-side.
- Cap maximum quantities.

### **Test 3: Bypassing Discount Validation**

Test whether discounts can be manipulated in an API.

**Steps**:
1. **Capture API Request**:
   - In Postman, send:
     ```json
     POST /api/v1/checkout
     {"discount_code": "SAVE10", "total": 100.00}
     ```
2. **Modify Discount**:
   - Change to `discount_code=SAVE100` (invalid code).
   - Send request.
3. **Verify**:
   - Check if discount is applied.

**Example Insecure Finding**:
- Response: `{"total": 0.00}`

**Example Secure Configuration**:
- Validate discount codes:
  ```python
  valid_codes = ['SAVE10', 'SAVE20']
  if request.json['discount_code'] not in valid_codes:
      return jsonify({'error': 'Invalid discount'}), 400
  ```

**Remediation**:
- Maintain a server-side list of valid codes.
- Limit discount percentages.

### **Test 4: Invalid Account Balance Update**

Test whether an application allows negative or unauthorized balance updates.

**Steps**:
1. **Capture Request**:
   - In Burp Suite, capture:
     ```
     POST /account/deposit HTTP/1.1
     Host: example.com
     amount=50.00
     ```
2. **Modify Amount**:
   - Change `amount=50.00` to `amount=-100.00`.
   - Send request.
3. **Verify**:
   - Check if balance decreases.

**Example Insecure Finding**:
- Response: `Balance: -$100.00`

**Example Secure Configuration**:
- Validate amount:
  ```php
  if ($_POST['amount'] <= 0) {
      die('Invalid amount');
  }
  ```

**Remediation**:
- Enforce positive amounts server-side.
- Implement transaction logging.

## **Additional Tips**

- **Understand Business Rules**: Study the application’s intended logic (e.g., pricing, discounts) to identify validation points.
- **Combine Tools**: Use Burp Suite for initial capture, Postman for APIs, and Python for automation.
- **Gray-Box Testing**: If documentation is available, check for expected input ranges or rules.
- **Document Thoroughly**: Save all requests, responses, and screenshots in a report.
- **Bypass Defenses**: Test edge cases (e.g., decimal values, null inputs) to uncover weak validation.
- **Stay Ethical**: Obtain explicit permission for active testing and avoid disrupting live systems.
- **Follow Best Practices**: Refer to OWASP’s Business Logic Testing section for additional techniques: [OWASP WSTG Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/).[](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/00-Introduction_to_Business_Logic)