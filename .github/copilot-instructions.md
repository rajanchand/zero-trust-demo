## Repo snapshot & purpose
This is an Express + MongoDB single-repo demo that implements Zero Trust patterns for an MSc dissertation. Key concepts implemented: password+OTP authentication, device fingerprinting & approval workflow, risk scoring (0–100), a central policy engine (ALLOW / DENY / STEP_UP), role-based access control (user, supervisor, admin, superadmin), continuous verification middleware and comprehensive audit logging.

## High-level architecture (what to know first)
- server entry: `server.js` (Express app, static frontend in `public/`).
- API layer: `routes/*.js` (auth, users, devices, admin). Routes typically apply middleware in this order: `authenticate` -> `continuousVerify(...)` -> `authorize(...)` (see usages in `routes/users.js`, `routes/devices.js`).
- Middleware: `middleware/auth.js` (JWT check), `middleware/continuousVerify.js` (risk/geo/device/policy decisions), `middleware/rbac.js` (role guard).
- Core decision code: `utils/policyEngine.js` (policy rules), `utils/riskScorer.js` (factors & scoring), `utils/auditLogger.js` (writes audit entries to DB).
- Data layer: `models/` (User, Device, OTP, RefreshToken, AuditLog). Refresh tokens are stored hashed and rotated (`routes/auth.js`).

## Critical runtime flows & developer touchpoints
- Login flow: `routes/auth.js` — POST `/api/auth/login` (email+password) → server prints OTP to console; POST `/api/auth/verify-otp` issues JWT + refresh token. The OTP mechanism is demo-only (printed to the server console).
- Device fingerprint: frontend generates it in `public/js/app.js` (function `getDeviceFingerprint()`), sent as header `X-Device-Fingerprint`. Backend expects `x-device-fingerprint` header.
- Tokens: access token is JWT in `Authorization: Bearer <token>`; refresh workflow at `/api/auth/refresh` uses hashed tokens in `RefreshToken` model. Step-up OTPs are created via `/api/auth/step-up` and expected as header `X-Step-Up-Token` for destructive endpoints.
- Continuous verification: `continuousVerify(sensitivity)` (see `middleware/continuousVerify.js`) calculates context (IP, geo, device, impossible travel, proxy), calls `calculateRisk()` and `evaluatePolicy()` and logs via `logAudit()`. It fails-closed on internal errors (deny on error).

## Where to change security behavior
- Policy rules: `utils/policyEngine.js` — rules are an ordered list; first match wins. Edit or add rules here for ALLOW/DENY/STEP_UP decisions.
- Risk factors & weights: `utils/riskScorer.js` — adjust numeric weights and thresholds here; risk level mapping to LOW/MEDIUM/HIGH is defined here.
- Device model & lifecycle: `models/Device.js` (registered as PENDING → TRUSTED → BLOCKED). Device approval endpoints: `routes/devices.js`.
- Audit shape: `utils/auditLogger.js` writes `models/AuditLog.js` entries. Keep logging calls idempotent (they swallow errors to avoid crashes).

## Project-specific conventions & patterns
- Middleware order matters: routes apply `authenticate` (auth) before `continuousVerify` (trust check) and `authorize` (role). Many routes call `continuousVerify()` with an endpoint sensitivity string (e.g. `'supervisor'`, `'admin'`, `'destructive'`) — use the same pattern.
- Decisions are centralized: prefer changing `policyEngine` and `riskScorer` rather than scattering conditional checks across routes.
- OTP delivery is intentionally mock: OTP values are printed to the server console. When modifying OTP delivery, search `routes/auth.js` for `console.log` blocks.
- Database reads often use `.lean()` for controller responses; follow that convention to avoid returning Mongoose documents where plain objects are expected.

## Useful filenames & examples (copyable patterns)
- Protect a route: router.get('/x', authenticate, continuousVerify('supervisor'), authorize('supervisor','admin'), handler)
- Read client fingerprint in backend: `const fingerprint = req.headers['x-device-fingerprint'] || 'unknown';`
- Force step-up: policy engine returns `decision: 'STEP_UP'` → API responds with `{ code: 'STEP_UP_REQUIRED' }`; frontend shows an OTP prompt.
- Add a policy rule (example in `utils/policyEngine.js`): new rule objects have `id`, `description`, `match(ctx)`, `decision`, `reason`.

## Dev / run commands (as used by this repo)
- Install: `npm install`
- Seed demo accounts: `npm run seed` (creates superadmin/admin/supervisor/user with demo passwords; see `scripts/seed.js` and README)
- Start in dev mode (nodemon): `npm run dev` or production: `npm start`

## Environment & runtime knobs (commonly changed)
- JWT secrets & expiries: `JWT_ACCESS_SECRET`, `JWT_ACCESS_EXPIRY`, `JWT_REFRESH_EXPIRY`.
- OTP expiry: `OTP_EXPIRY_MINUTES`.
- Lockout & rate-limiting: `MAX_FAILED_LOGINS`, `LOCKOUT_DURATION_MINUTES`, `RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX`.

## Testing / debugging tips
- OTPs are printed to the server console — watch terminal output when performing login flows.
- Useful logs: `console.log` blocks are present in `routes/auth.js` (OTP output) and `server.js` (startup & DB connect). Add temporary logs near `logAudit()` calls to trace decisions without modifying policy code.
- To simulate different risk factors: change device fingerprint (clear localStorage key `zt_device_id` in browser), alter IP/geo behavior by mocking `geoLookup()` in `utils/geoLookup.js`, or tweak `riskScorer` values.

## When to ask for human review (PR guidance)
- Any change to `policyEngine.js` or `riskScorer.js` should include: rationale, unit examples (input→expected decision), and a short run-through using the demo accounts.
- Changes that touch token rotation / refresh flows or OTP storage must be reviewed for security (look at `routes/auth.js`, `models/RefreshToken.js`, `models/OTP.js`).

If anything here is unclear or you'd like examples added (e.g., a small unit test harness for policy rules), tell me which section to expand and I will iterate.
