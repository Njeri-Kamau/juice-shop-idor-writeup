
# Vulnerability Assessment Report: Insecure Direct Object Reference (IDOR) on OWASP Juice Shop

## ⚠️ Disclaimer
This security write-up and proof-of-concept (PoC) were conducted strictly for educational, security research, and portfolio demonstration purposes within a controlled, local sandbox environment (`localhost`). No unauthorized testing or malicious targeting was performed against external systems.

---

## **1. Executive Summary**
An **Insecure Direct Object Reference (IDOR)** / **Broken Object Level Authorization (BOLA)** vulnerability was identified in the REST API endpoint `/rest/basket/{id}` of OWASP Juice Shop. The application fails to validate whether the authenticated user issuing the HTTP request owns the requested shopping basket resource.

By manipulating the `id` path parameter in the HTTP GET request, an authenticated attacker can access, view, and enumerate the private shopping cart contents and associated internal `UserId` of any platform user.

---

## **2. Vulnerability Details**
* **Vulnerability Type:** Insecure Direct Object Reference (IDOR) / Broken Object Level Authorization (BOLA)
* **CWE Mapping:** [CWE-639: Access Control Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* **OWASP Top 10 Category:** A01:2021 – Broken Access Control
* **Vulnerable Endpoint:** `http://localhost:3000/rest/basket/{id}`
* **HTTP Method:** `GET`
* **Vulnerable Parameter:** `{id}` (Path Parameter)

---

## **3. Risk Assessment & Severity**
* **CVSS v3.1 Base Score:** **6.5 (Medium)**
* **CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

| Metric | Rating | Rationale |
| :--- | :--- | :--- |
| **Attack Vector (AV)** | Network | Exploitable remotely over HTTP/HTTPS. |
| **Attack Complexity (AC)** | Low | Requires no specialized conditions or complex timing. |
| **Privileges Required (PR)** | Low | Requires a standard authenticated user session. |
| **User Interaction (UI)** | None | No victim interaction is required for exploitation. |
| **Scope (S)** | Unchanged | Impact is confined to the target platform application context. |
| **Confidentiality (C)** | High | Full exposure of all platform users' cart items and mapped user IDs. |
| **Integrity (I)** | None | Read-only data exposure via `GET` requests. |
| **Availability (A)** | None | Application stability is unaffected. |

---

## **4. Prerequisites & Environment**
* **Target Environment:** Docker container running OWASP Juice Shop on `localhost:3000`.
* **Testing Tooling:** Burp Suite Community Edition, Mozilla Firefox configured to route traffic through Burp Proxy (`127.0.0.1:8080`).

---

## **5. Step-by-Step Proof of Concept (PoC)**

### **Step 1: Application Setup**
The target environment was deployed locally using Docker:

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
Figure 1: OWASP Juice Shop listening on local port 3000.

Step 2: Intercepting Traffic & Session Analysis
Proxy interception was enabled in Burp Suite while navigating the application interface to observe application endpoints and HTTP requests.

Figure 2: Initial HTTP GET request captured in Burp Proxy Intercept.

Figure 3: HTTP history capturing API communication patterns.

Figure 4: Inspecting current user identity via /rest/user/whoami.

Step 3: Intercepting Legitimate Basket Fetch
Navigating to Your Basket inside the web app triggered a legitimate API call to fetch the logged-in user's shopping basket ID (/rest/basket/6).

Figure 5: Capturing legitimate basket request GET /rest/basket/6 with Bearer Token.

Step 4: Parameter Manipulation via Repeater
The request was forwarded to Burp Repeater (Ctrl + R) for iterative testing. The id path parameter was altered from 6 to target other sequential integer values.

Figure 6: Request loaded into Burp Repeater tab.

Figure 7: Modifying request parameters and headers.

Step 5: Exploitation & Unauthorized Data Disclosure
Sending requests with modified id values yielded full JSON payload responses for carts belonging to other platform users without authorization errors.

Figure 8: Server returning HTTP 200 OK with basket data for ID 6.

Figure 9: Server returning HTTP 200 OK with basket data for ID 1.

JSON
{
  "status": "success",
  "data": {
    "id": 1,
    "coupon": null,
    "UserId": 1,
    "createdAt": "2026-09-04T09:30:23.861Z",
    "updatedAt": "2026-09-04T09:30:23.861Z",
    "Products": [ ... ]
  }
}
Figure 10: Client-side web basket view reflecting loaded product records.

6. Impact Analysis
Mass Data Harvesting: An attacker can script simple sequential loops (1 through N) to extract every user cart stored in the database.

Privacy Violation: Exposes user purchasing choices, item quantities, applied promo codes, and correlates cart identifiers with internal UserId values.

7. Remediation Recommendations
Implement Server-Side Access Control Checks:
Verify that the UserId stored in the decoded JWT session token strictly matches the UserId associated with the requested Basket record before returning data.

JavaScript
app.get('/rest/basket/:id', verifyToken, async (req, res) => {
  const basket = await Basket.findByPk(req.params.id);

  if (!basket) {
    return res.status(404).json({ status: 'error', message: 'Basket not found' });
  }

  if (basket.UserId !== req.user.id) {
    return res.status(403).json({ status: 'error', message: 'Access denied: Unauthorized access to resource.' });
  }

  return res.json({ status: 'success', data: basket });
});
Use Non-Sequential Identifiers:
Replace predictable sequential integer IDs (1, 2, 3) with cryptographically secure UUIDs (v4) to prevent resource enumeration attacks.


<Elicitations message="What would you like to do next?">
  <Elicitation label="Confirm preview screenshot" query="Here is a screenshot of the preview after pasting the full report."/>
  <Elicitation label="Pin repo to GitHub profile" query="How do I pin this published repository to my GitHub profile?"/>
</Elicitations>
