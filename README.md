# Zero Trust Security Demo Website

**MSc Dissertation – University of the West of Scotland (UWS)**

A demonstration website implementing Zero Trust Security principles including strong authentication, OTP verification, RBAC, device fingerprinting, risk scoring, a centralized policy engine, continuous verification, and audit logging.

---

## 📁 Project Structure

```
zero trust code/
├── server.js                    # Express server entry point
├── package.json                 # Dependencies
├── .env                         # Environment variables
├── .env.example                 # Template for .env
│
├── models/                      # Mongoose database models
│   ├── User.js                  # User accounts, roles, lockout
│   ├── Device.js                # Device fingerprints & approval status
│   ├── RefreshToken.js          # Hashed refresh tokens (rotation)
│   ├── OTP.js                   # One-time passwords (login + step-up)
│   └── AuditLog.js              # Comprehensive audit trail
│
├── routes/                      # Express API routes
│   ├── auth.js                  # Login, OTP, refresh, logout, step-up
│   ├── users.js                 # CRUD user management
│   ├── devices.js               # Device approval workflow
│   └── admin.js                 # Dashboard stats, logs, policy rules
│
├── middleware/                   # Express middleware
│   ├── auth.js                  # JWT authentication
│   ├── rbac.js                  # Role-Based Access Control
│   └── continuousVerify.js      # Zero Trust continuous verification
│
├── utils/                       # Backend utilities
│   ├── auditLogger.js           # Writes audit log entries
│   ├── geoLookup.js             # IP → Country lookup (free API)
│   ├── helpers.js               # IP parsing, browser detection, OTP gen
│   ├── passwordPolicy.js        # Password strength validation
│   ├── policyEngine.js          # Central ALLOW/DENY/STEP_UP engine
│   └── riskScorer.js            # Risk score calculator (0–100)
│
├── scripts/
│   └── seed.js                  # Creates default demo accounts
│
└── public/                      # Frontend (static files)
    ├── index.html               # Single-page application shell
    ├── css/
    │   └── style.css            # All styles
    └── js/
        └── app.js               # All client-side logic
```

---

## 🚀 Step-by-Step Setup Guide (VS Code)

### Prerequisites
- **Node.js** v18 or higher → [Download](https://nodejs.org)
- **MongoDB** running locally on port 27017 → [Download](https://www.mongodb.com/try/download/community)
  - Or use MongoDB Atlas (update `MONGO_URI` in `.env`)

### Steps

**1. Open the project folder in VS Code**

Open `zero trust code/` folder in VS Code.

**2. Open a terminal in VS Code** (`Terminal → New Terminal` or `` Ctrl+` ``)

**3. Install dependencies**
```bash
npm install
```

**4. Make sure MongoDB is running**
```bash
# If using Homebrew on macOS:
brew services start mongodb-community

# Or start manually:
mongod --dbpath /path/to/data
```

**5. Configure environment variables**

The `.env` file is already created with defaults. Edit it if needed:
```bash
# For custom MongoDB URL (e.g., Atlas):
MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/zero_trust_demo
```

**6. Seed the database with demo accounts**
```bash
npm run seed
```
This creates 4 accounts:
| Email | Password | Role |
|---|---|---|
| superadmin@demo.com | Password@123 | superadmin |
| admin@demo.com | Password@123 | admin |
| supervisor@demo.com | Password@123 | supervisor |
| user@demo.com | Password@123 | user |

**7. Start the server**
```bash
npm run dev
```
Or without nodemon:
```bash
npm start
```

**8. Open the website**

Go to [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🖥️ Pages & Features

### 1. Login Page
- Enter email and password
- Shows demo account credentials for convenience
- On success → sends OTP (printed in the **server console**)
- Account lockout after 5 failed attempts (15 min)

### 2. OTP Verification Page
- Enter the 6-digit OTP from the server console
- On verification → JWT access token + refresh token issued
- Device fingerprint registered (new devices start as PENDING)

### 3. Dashboard
- Shows current user session info (email, role, IP, country, browser, OS)
- Device fingerprint and approval status
- **Risk assessment**: current risk score, level, factors
- **System statistics** (admin/superadmin only): user counts, device counts, login/denial stats for last 24 hours
- Device pending banner if device not yet approved

### 4. User Management (supervisor+)
- Create new users (supervisors can only create 'user' role)
- View all users with their roles, status, failed login count
- Admins can: change roles, enable/disable accounts, delete users
- Delete triggers step-up OTP if risk score is elevated

### 5. Device Management (supervisor+)
- **Pending Devices**: list of devices awaiting approval
- **All Devices**: all registered devices with status (PENDING/TRUSTED/BLOCKED)
- Approve or block devices
- Shows fingerprint, browser, OS, first/last seen, approved by

### 6. Audit Logs (admin+)
- Comprehensive audit trail of all system events
- Filterable by: actor (email), action type, decision (ALLOW/DENY/STEP_UP), date range
- Each log shows: timestamp, actor, role, action, endpoint, decision, risk score, IP, country, device fingerprint, matched policy rule
- Paginated

### 7. Policy Rules (superadmin only)
- Displays all current Zero Trust policy engine rules
- Shows rule ID, description, decision type, and reason
- Risk scoring factors table with point values
- Risk level thresholds

---

## 🔐 Zero Trust Concepts Demonstrated

| Concept | Implementation |
|---|---|
| **Strong Authentication** | Password + OTP (two-factor) |
| **RBAC** | 4 roles with granular permissions |
| **Device Trust** | Fingerprinting + approval workflow |
| **Network Context** | IP geo-lookup, proxy detection |
| **Risk Scoring** | Rules-based engine (0–100) |
| **Policy Engine** | Central ALLOW/DENY/STEP_UP decisions |
| **Continuous Verification** | Every API request re-evaluated |
| **Least Privilege** | Minimal access per role |
| **Session Management** | Short-lived JWT + refresh rotation |
| **Idle Timeout** | Frontend inactivity detection |
| **Audit Logging** | All actions logged with full context |
| **Account Lockout** | Brute-force protection |
| **Rate Limiting** | Per-IP request throttling |
| **Step-Up Auth** | Re-authentication for sensitive actions |

---

## ⚠️ Demo Notes

- **OTP delivery is simulated**: OTP codes are printed to the server console (not sent via email/SMS). This is clearly logged as a demo simulation.
- **Geo-lookup**: Uses the free `ip-api.com` API. From localhost, country will show as "Local".
- **Proxy/VPN detection**: Uses header heuristics + geo API flag. Clearly labelled as demo/simulated.
- **Device fingerprint**: Generated from browser properties + localStorage ID. Not as robust as production solutions but demonstrates the concept.

---

## 📝 License

This project is for academic/dissertation purposes at UWS.
