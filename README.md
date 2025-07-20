# Authentication-Nodejs-and-ExpressJs

## **Overview**

This system provides secure user authentication using:

* **OTP Verification** (during signup)
* **JWT Token (via HTTP-Only Cookies)** (for session management)
* **Middleware** (to protect APIs)

---

## **Process Flow**

### **1️⃣ Signup + OTP Verification**

* User calls **`/signup`** API with name, email, password, and mobile.
* Server generates a **6-digit OTP** and saves it to `otp.json`.
* OTP is printed in the **terminal** (simulating SMS/Email delivery).
* User calls **`/verify-otp`** API to submit the OTP.
* On success, the OTP is deleted and the user is verified.

---

### **2️⃣ Login & Session Handling**

* User calls **`/login`** with email/mobile + password.
* Server creates a **JWT token** and sends it via **HTTP-Only Cookie** named `sessionToken`.
* This cookie is used for session management in the browser or `curl`.

---

### **3️⃣ Middleware Protection**

* Middleware reads the `sessionToken` cookie.
* Verifies the JWT.
* If valid, user can access **protected routes**.
* If invalid or missing, returns **401 Unauthorized**.

---

## **Password Constraints**

During **signup**, passwords must:

* Be **at least 8 characters**
* Include **1 uppercase**, **1 lowercase**, **1 number**, and **1 special character**

Example valid password:
`Test@1234`

---

## **Test Commands**

### **1️⃣ Signup**

```bash
curl -X POST http://localhost:3000/signup \
  -H "Content-Type: application/json" \
  -d '{
    "name": "TestUser",
    "email": "test@example.com",
    "password": "Test@1234",
    "mobile": "9999990000"
  }'
```

---

### **2️⃣ Verify OTP**

(Replace `123456` with the OTP printed in your terminal)

```bash
curl -X POST http://localhost:3000/verify-otp \
  -H "Content-Type: application/json" \
  -d '{
    "identifier": "test@example.com",
    "otp": "123456"
  }'
```

---

### **3️⃣ Login (Save Cookie)**

```bash
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{
    "identifier": "test@example.com",
    "password": "Test@1234"
  }'
```

---

### **4️⃣ Access Protected Route**

```bash
curl -X GET http://localhost:3000/protected \
  -b cookies.txt
```

---

### **5️⃣ Refresh Token (Dummy Refresh)**

```bash
curl -X POST http://localhost:3000/refresh-token \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{
    "refreshToken": "dummy-refresh-token"
  }'
```

---

## **Summary Table**

| Component  | Purpose                             |
| ---------- | ----------------------------------- |
| OTP        | Verifies user during signup         |
| Cookies    | Maintains session securely          |
| Middleware | Protects API routes with JWT checks |

---

## **Files Used**

* `users.json` – Stores registered users.
* `otp.json` – Temporarily stores OTPs.

---

## **Security Notes**

* Cookies are **HTTP-Only** (prevents XSS)
* JWT is used for **stateless session management**
* OTP has **5-minute expiry**


