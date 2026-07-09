# Secure E-Commerce Platform - 'The ABC Shop'

A prototype security-first e-commerce web application designed for **Amazing Bargain Central Ltd. (The ABC Shop)**. This project demonstrates how SMEs can build lightweight web applications backed by robust, industry-standard security controls.

---

## Repository Structure

* **`static/css/` & `templates/`** – Frontend stylesheets and Jinja2 HTML templates (View layer).
* **`uploads/`** – Restricted directory for user-submitted product images.
* **`Main.py`** – Core application logic, routing controller, and back-end security features.
* **`create_admin.py` & `create_seller.py`** – Initialization scripts to securely provision system accounts.
* **`database.db`** – SQLite database tracking Users, Products, Orders, and Audit logs.
* **`secret.env`** – Protected configuration file containing cryptographic keys.

---

## Tech Stack & Architecture

The system implements a classic **Model-View-Controller (MVC)** architectural pattern:
* **Backend:** Python (Flask)
* **Database:** SQLite3 (Relational engine tracking users, products, orders, and system logs)
* **Development IDE:** Visual Studio Code

---

##  Implemented Security Features

### 1. Authentication & Role-Based Access Control (RBAC)
* **Password Hashing:** Salted, cryptographic one-way hashing via `werkzeug.security`.
* **Granular RBAC Decorators:** Custom rules restricting resources based on user role (`@login_required`, `@seller_required`, `@admin_required`).

### 2. Injection & Cross-Site Scripting (XSS) Defenses
* **Parameterized Queries:** Uses `sqlite3` placeholder tokens (`?`) to immunize data transaction pipelines against SQL Injection.
* **Input Sanitization:** Aggressively strips dangerous HTML tags globally using the `bleach` library.

### 3. Session Management & Browser Protections
* **Signed Cookies & CSRF Shielding:** Protects session payloads with random 24-byte signing tokens and enforces `Flask_WTF.csrf` protection.
* **Security Headers:** Mitigates clickjacking and framing tricks using `SameSite=Lax`, `X-Frame-Options: SAMEORIGIN`, and `X-Content-Type-Options: nosniff`.

### 4. File Upload Isolation
* Enforces strong filename isolation filters via `secure_filename` to prevent path traversal risks, limits uploads to explicitly whitelisted extensions (`png`, `jpg`, `jpeg`, `gif`), and appends User ID tags to prevent overwrites.

---

## Security Audit & Mitigation Ledger

The repository's overall posture has been audited against the **NIST Cybersecurity Framework** using static code analysis (**Bandit**) and dynamic scanning (**OWASP ZAP**).

| Tool | Vulnerability Discovered | Risk Level | Applied Mitigation & Technical Impact |
| :--- | :--- | :--- | :--- |
| **Bandit** | Flask Root Running with `debug=True` | **High** | Switched initialization to `debug=False` for production to prevent arbitrary code execution. |
| **OWASP ZAP** | Absence of Anti-CSRF Tokens | **Medium** | Configured `CSRFProtect(app)` using a secure token key to prevent session rider vectors. |
| **OWASP ZAP** | Missing Anti-Clickjacking Header | **Medium** | Appended custom global request processors returning `X-Frame-Options: SAMEORIGIN`. |
| **OWASP ZAP** | Cookie Missing SameSite Properties | **Low** | Set baseline configurations explicitly to use `SESSION_COOKIE_SAMESITE = 'Lax'`. |

---

## Installation & Running Locally

### 1. Requirements Setup
Install the necessary dependencies via `pip`:
```bash
pip install flask Flask-WTF bleach python-dotenv
