/**
 * Zero Trust Security Demo – Frontend Application
 * ═════════════════════════════════════════════════
 * Vanilla JavaScript – no frameworks needed.
 *
 * Features:
 *  - Device fingerprinting
 *  - Login + OTP flow
 *  - Token management (access + refresh)
 *  - Idle timeout detection
 *  - Page navigation
 *  - API calls with auth headers
 *  - Admin dashboard, user/device management, logs, policy view
 */

// ─── State ──────────────────────────────────────────────
let accessToken = null;
let refreshToken = null;
let otpToken = null;
let currentUser = null;
let stepUpToken = null;
let stepUpCallback = null;
let idleTimer = null;
let idleWarningTimer = null;
const IDLE_TIMEOUT = 10 * 60 * 1000;        // 10 min idle → warning
const IDLE_LOGOUT = 12 * 60 * 1000;         // 12 min idle → auto logout
const TOKEN_REFRESH_INTERVAL = 13 * 60 * 1000; // Refresh before 15 min expiry

// ─── Device Fingerprint ─────────────────────────────────
// Generate a stable-ish fingerprint from browser properties.
// Uses localStorage to persist a random component.
function getDeviceFingerprint() {
  let storedId = localStorage.getItem('zt_device_id');
  if (!storedId) {
    storedId = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
    localStorage.setItem('zt_device_id', storedId);
  }

  const raw = [
    navigator.userAgent,
    navigator.platform,
    Intl.DateTimeFormat().resolvedOptions().timeZone,
    screen.width + 'x' + screen.height,
    storedId
  ].join('|');

  // Simple hash (not cryptographic – just for fingerprinting)
  let hash = 0;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw.charCodeAt(i);
    hash = ((hash << 5) - hash) + ch;
    hash = hash & hash; // Convert to 32bit int
  }
  return 'fp_' + Math.abs(hash).toString(16);
}

const deviceFingerprint = getDeviceFingerprint();

// ─── API Helper ─────────────────────────────────────────
async function api(url, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    'X-Device-Fingerprint': deviceFingerprint,
    ...options.headers
  };

  if (accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }

  if (stepUpToken) {
    headers['X-Step-Up-Token'] = stepUpToken;
  }

  const response = await fetch(url, {
    ...options,
    headers
  });

  // Handle token expiry
  if (response.status === 401) {
    const data = await response.json();
    if (data.code === 'TOKEN_EXPIRED' && refreshToken) {
      const refreshed = await refreshAccessToken();
      if (refreshed) {
        // Retry the original request
        headers['Authorization'] = `Bearer ${accessToken}`;
        return fetch(url, { ...options, headers });
      }
    }
    // Session replaced by another login
    if (data.code === 'SESSION_REPLACED') {
      alert('⚠️ Your session was terminated because your account was logged in from another location.');
      logout();
      return response;
    }
    // If refresh failed, log out
    logout();
    return response;
  }

  // Handle suspicious lock
  if (response.status === 423) {
    const data = await response.json();
    if (data.code === 'SUSPICIOUS_LOCK') {
      alert(`🔒 Account temporarily locked due to suspicious activity.\n${data.error}`);
      logout();
      return response;
    }
  }

  // Handle mid-session step-up required (IP change, risk spike)
  if (response.status === 403) {
    const cloned = response.clone();
    try {
      const data = await cloned.json();
      if (data.code === 'STEP_UP_REQUIRED' && data.rule &&
          (data.rule.includes('SESSION_IP') || data.rule.includes('HIGH_RISK'))) {
        showStepUpAlert(data.reason || 'Additional verification required due to suspicious activity.');
      }
    } catch { /* not JSON, ignore */ }
  }

  return response;
}

// ─── Token Refresh ──────────────────────────────────────
async function refreshAccessToken() {
  try {
    const res = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken })
    });
    if (res.ok) {
      const data = await res.json();
      accessToken = data.accessToken;
      refreshToken = data.refreshToken;
      saveSession();
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

// ─── Session Persistence ────────────────────────────────
function saveSession() {
  sessionStorage.setItem('zt_access', accessToken || '');
  sessionStorage.setItem('zt_refresh', refreshToken || '');
  sessionStorage.setItem('zt_user', JSON.stringify(currentUser || {}));
}

function loadSession() {
  accessToken = sessionStorage.getItem('zt_access') || null;
  refreshToken = sessionStorage.getItem('zt_refresh') || null;
  const u = sessionStorage.getItem('zt_user');
  currentUser = u ? JSON.parse(u) : null;
}

function clearSession() {
  accessToken = null;
  refreshToken = null;
  currentUser = null;
  stepUpToken = null;
  sessionStorage.clear();
}

// ─── Page Navigation ────────────────────────────────────
function showPage(pageName) {
  // Hide all pages
  document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));

  // Show target page
  const page = document.getElementById(`page-${pageName}`);
  if (page) page.classList.remove('hidden');

  // Update active nav link
  document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
  const activeLink = document.querySelector(`.nav-link[onclick*="${pageName}"]`);
  if (activeLink) activeLink.classList.add('active');

  // Load page data
  if (pageName === 'dashboard') loadDashboard();
  if (pageName === 'users') loadUsers();
  if (pageName === 'devices') loadDevices();
  if (pageName === 'logs') loadLogs();
  if (pageName === 'policy') loadPolicy();
}

function showAuthPage(pageName) {
  document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
  document.getElementById(`page-${pageName}`).classList.remove('hidden');
  document.getElementById('mainNav').classList.add('hidden');
}

// ─── Login Handler ──────────────────────────────────────
async function handleLogin(e) {
  e.preventDefault();
  const email = document.getElementById('loginEmail').value.trim();
  const password = document.getElementById('loginPassword').value;
  const errEl = document.getElementById('loginError');
  const btn = document.getElementById('loginBtn');

  errEl.classList.add('hidden');
  btn.disabled = true;
  btn.textContent = 'Logging in...';

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-Fingerprint': deviceFingerprint
      },
      body: JSON.stringify({ email, password, deviceFingerprint })
    });

    const data = await res.json();

    if (!res.ok) {
      errEl.textContent = data.error || 'Login failed';
      errEl.classList.remove('hidden');
      btn.disabled = false;
      btn.textContent = 'Login';
      return;
    }

    // Store OTP token and go to OTP page
    otpToken = data.otpToken;
    showAuthPage('otp');
    document.getElementById('otpInput').focus();

    // Show OTP delivery info
    const otpHint = document.getElementById('otpDemoHint');
    if (otpHint) {
      if (data.otpSentVia === 'email') {
        otpHint.textContent = '📧 OTP sent to your email! Check your inbox.';
        otpHint.style.background = '#1a3a5a';
        otpHint.style.color = '#60a5fa';
        otpHint.classList.remove('hidden');
      } else if (data.demoOTP) {
        otpHint.textContent = `Demo OTP: ${data.demoOTP}`;
        otpHint.style.background = '#1a5a1a';
        otpHint.style.color = '#4ade80';
        otpHint.classList.remove('hidden');
      }
    }

  } catch (err) {
    errEl.textContent = 'Network error. Is the server running?';
    errEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Login';
  }
}

// ─── OTP Verify Handler ────────────────────────────────
async function handleOTPVerify(e) {
  e.preventDefault();
  const otp = document.getElementById('otpInput').value.trim();
  const errEl = document.getElementById('otpError');
  const btn = document.getElementById('otpBtn');

  errEl.classList.add('hidden');
  btn.disabled = true;
  btn.textContent = 'Verifying...';

  try {
    const res = await fetch('/api/auth/verify-otp', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-Fingerprint': deviceFingerprint
      },
      body: JSON.stringify({ otp, otpToken, deviceFingerprint })
    });

    const data = await res.json();

    if (!res.ok) {
      errEl.textContent = data.error || 'OTP verification failed';
      errEl.classList.remove('hidden');
      btn.disabled = false;
      btn.textContent = 'Verify OTP';
      return;
    }

    // Login success!
    accessToken = data.accessToken;
    refreshToken = data.refreshToken;
    currentUser = data.user;
    otpToken = null;

    saveSession();
    enterApp();

  } catch (err) {
    errEl.textContent = 'Network error';
    errEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Verify OTP';
  }
}

function backToLogin() {
  otpToken = null;
  showAuthPage('login');
}

// ─── Enter App ──────────────────────────────────────────
function enterApp() {
  document.getElementById('mainNav').classList.remove('hidden');

  // Set user info in nav
  const role = currentUser?.role || 'user';
  document.getElementById('navUserInfo').textContent = `${currentUser?.email} (${role})`;

  // Show/hide nav links based on role
  const isSupervisor = ['supervisor', 'admin', 'superadmin'].includes(role);
  const isAdmin = ['admin', 'superadmin'].includes(role);
  const isSuperadmin = role === 'superadmin';

  document.getElementById('navUsers').classList.toggle('hidden', !isSupervisor);
  document.getElementById('navDevices').classList.toggle('hidden', !isSupervisor);
  document.getElementById('navLogs').classList.toggle('hidden', !isAdmin);
  document.getElementById('navPolicy').classList.toggle('hidden', !isSuperadmin);

  showPage('dashboard');
  startIdleTimer();
  startTokenRefreshLoop();
}

// ─── Logout ─────────────────────────────────────────────
async function logout() {
  try {
    await api('/api/auth/logout', {
      method: 'POST',
      body: JSON.stringify({ refreshToken })
    });
  } catch { /* ignore */ }

  clearSession();
  stopIdleTimer();
  showAuthPage('login');
  document.getElementById('loginForm').reset();
  document.getElementById('otpForm').reset();
}

// ─── Dashboard ──────────────────────────────────────────
async function loadDashboard() {
  try {
    const res = await api('/api/users/me');
    if (!res.ok) return;

    const data = await res.json();
    const user = data.user;
    const risk = data.riskContext || {};
    const devices = data.devices || [];

    // Check device status
    const myDevice = devices.find(d => d.fingerprint === deviceFingerprint);
    const banner = document.getElementById('devicePendingBanner');
    if (myDevice && myDevice.status === 'PENDING') {
      banner.classList.remove('hidden');
    } else {
      banner.classList.add('hidden');
    }

    // Session info
    const sessionInfo = document.getElementById('sessionInfo');
    sessionInfo.innerHTML = `
      ${infoItem('Email', user.email)}
      ${infoItem('Role', user.role)}
      ${infoItem('Status', user.status)}
      ${infoItem('IP Address', risk.ip || 'N/A')}
      ${infoItem('Country', risk.country || 'N/A')}
      ${infoItem('Browser', risk.browser || 'N/A')}
      ${infoItem('OS', risk.os || 'N/A')}
      ${infoItem('Device Fingerprint', deviceFingerprint)}
      ${infoItem('Device Status', myDevice?.status || 'Unknown')}
      ${infoItem('Last Login', user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleString() : 'N/A')}
    `;

    // Risk info
    const riskInfo = document.getElementById('riskInfo');
    const riskClass = risk.riskLevel === 'HIGH' ? 'risk-high' : risk.riskLevel === 'MEDIUM' ? 'risk-medium' : 'risk-low';
    riskInfo.innerHTML = `
      <div class="info-grid">
        ${infoItem('Risk Score', `<span class="${riskClass}">${risk.riskScore ?? 'N/A'} / 100</span>`)}
        ${infoItem('Risk Level', `<span class="${riskClass}">${risk.riskLevel || 'N/A'}</span>`)}
        ${infoItem('Policy Decision', risk.policyDecision || 'N/A')}
        ${infoItem('Matched Rule', risk.policyRule || 'N/A')}
      </div>
      ${risk.ipChangedMidSession ? '<div class="alert alert-warning mt-1">⚠️ IP address changed during this session</div>' : ''}
      ${risk.countryChangedMidSession ? '<div class="alert alert-danger mt-1">🚨 Country changed during this session – possible session hijack</div>' : ''}
      ${risk.riskFactors && risk.riskFactors.length > 0 ? `
        <div class="mt-1">
          <strong>Risk Factors:</strong>
          <ul>${risk.riskFactors.map(f => `<li>${f}</li>`).join('')}</ul>
        </div>
      ` : '<p class="text-muted mt-1">No risk factors detected.</p>'}
    `;

    // Stats (admin+)
    const isAdmin = ['admin', 'superadmin'].includes(currentUser?.role);
    const statsSection = document.getElementById('statsSection');
    if (isAdmin) {
      statsSection.classList.remove('hidden');
      const statsRes = await api('/api/admin/stats');
      if (statsRes.ok) {
        const stats = await statsRes.json();
        document.getElementById('statsGrid').innerHTML = `
          ${statCard(stats.users.total, 'Total Users')}
          ${statCard(stats.users.active, 'Active Users')}
          ${statCard(stats.devices.total, 'Total Devices')}
          ${statCard(stats.devices.pending, 'Pending Devices')}
          ${statCard(stats.devices.trusted, 'Trusted Devices')}
          ${statCard(stats.last24h.logins, 'Logins (24h)')}
          ${statCard(stats.last24h.failedLogins, 'Failed Logins (24h)')}
          ${statCard(stats.last24h.denials, 'Policy Denials (24h)')}
        `;
      }
    } else {
      statsSection.classList.add('hidden');
    }

  } catch (err) {
    console.error('Dashboard load error:', err);
  }
}

function infoItem(label, value) {
  return `<div class="info-item"><div class="label">${label}</div><div class="value">${value}</div></div>`;
}

function statCard(value, label) {
  return `<div class="stat-card"><div class="stat-value">${value}</div><div class="stat-label">${label}</div></div>`;
}

// ─── Users Page ─────────────────────────────────────────
async function loadUsers() {
  try {
    // Restrict role dropdown for supervisors
    const roleSelect = document.getElementById('newUserRole');
    if (currentUser?.role === 'supervisor') {
      roleSelect.innerHTML = '<option value="user">User</option>';
    } else {
      roleSelect.innerHTML = `
        <option value="user">User</option>
        <option value="supervisor">Supervisor</option>
        <option value="admin">Admin</option>
      `;
    }

    const res = await api('/api/users');
    if (!res.ok) {
      const err = await res.json();
      if (err.code === 'STEP_UP_REQUIRED') {
        document.getElementById('usersTableBody').innerHTML =
          `<tr><td colspan="6" class="error-msg">🔐 Step-up authentication required to view users.</td></tr>`;
        initiateStepUp(() => loadUsers());
        return;
      }
      document.getElementById('usersTableBody').innerHTML =
        `<tr><td colspan="6" class="error-msg">${err.error || 'Failed to load users'}</td></tr>`;
      return;
    }

    const { users } = await res.json();
    const tbody = document.getElementById('usersTableBody');
    const isAdmin = ['admin', 'superadmin'].includes(currentUser?.role);

    if (users.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6">No users found</td></tr>';
      return;
    }

    tbody.innerHTML = users.map(u => `
      <tr>
        <td>${escapeHtml(u.email)}</td>
        <td><span class="badge badge-blue">${u.role}</span></td>
        <td><span class="badge ${u.status === 'active' ? 'badge-green' : 'badge-red'}">${u.status}</span></td>
        <td>${u.failedLoginAttempts || 0}</td>
        <td>${u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : 'Never'}</td>
        <td>
          ${isAdmin ? `
            <select onchange="changeRole('${u._id}', this.value)" class="btn btn-sm" style="padding: 2px 4px; font-size: 0.78rem;">
              <option value="" disabled selected>Change Role</option>
              <option value="user">User</option>
              <option value="supervisor">Supervisor</option>
              <option value="admin">Admin</option>
              ${currentUser?.role === 'superadmin' ? '<option value="superadmin">Superadmin</option>' : ''}
            </select>
            <button onclick="toggleUserStatus('${u._id}', '${u.status}')" class="btn btn-sm ${u.status === 'active' ? 'btn-warning' : 'btn-success'}">
              ${u.status === 'active' ? 'Disable' : 'Enable'}
            </button>
            <button onclick="deleteUser('${u._id}', '${escapeHtml(u.email)}')" class="btn btn-sm btn-danger">Delete</button>
          ` : '—'}
        </td>
      </tr>
    `).join('');

  } catch (err) {
    console.error('Users load error:', err);
  }
}

async function handleCreateUser(e) {
  e.preventDefault();
  const email = document.getElementById('newUserEmail').value.trim();
  const password = document.getElementById('newUserPassword').value;
  const role = document.getElementById('newUserRole').value;
  const msgEl = document.getElementById('createUserMsg');

  const res = await api('/api/users', {
    method: 'POST',
    body: JSON.stringify({ email, password, role })
  });

  const data = await res.json();
  msgEl.classList.remove('hidden');
  if (res.ok) {
    msgEl.className = 'success-msg';
    msgEl.textContent = `User ${data.user.email} created successfully`;
    document.getElementById('createUserForm').reset();
    loadUsers();
  } else if (data.code === 'STEP_UP_REQUIRED') {
    msgEl.className = 'error-msg';
    msgEl.textContent = '🔐 Step-up authentication required. Verifying identity...';
    initiateStepUp(() => handleCreateUser(e));
  } else {
    msgEl.className = 'error-msg';
    msgEl.textContent = data.error + (data.details ? ': ' + data.details.join(', ') : '');
  }
  setTimeout(() => msgEl.classList.add('hidden'), 8000);
}

async function changeRole(userId, newRole) {
  if (!newRole) return;
  const res = await api(`/api/users/${userId}/role`, {
    method: 'PUT',
    body: JSON.stringify({ role: newRole })
  });
  const data = await res.json();
  if (res.ok) {
    loadUsers();
  } else {
    alert(data.error || 'Failed to change role');
  }
}

async function toggleUserStatus(userId, currentStatus) {
  const newStatus = currentStatus === 'active' ? 'disabled' : 'active';
  const res = await api(`/api/users/${userId}`, {
    method: 'PUT',
    body: JSON.stringify({ status: newStatus })
  });
  if (res.ok) {
    loadUsers();
  } else {
    const data = await res.json();
    alert(data.error || 'Failed to update user');
  }
}

async function deleteUser(userId, email) {
  if (!confirm(`Are you sure you want to delete ${email}?`)) return;

  const res = await api(`/api/users/${userId}`, { method: 'DELETE' });
  const data = await res.json();

  if (res.ok) {
    loadUsers();
  } else if (data.code === 'STEP_UP_REQUIRED') {
    // Need step-up auth
    initiateStepUp(() => deleteUserWithStepUp(userId));
  } else {
    alert(data.error || 'Failed to delete user');
  }
}

async function deleteUserWithStepUp(userId) {
  const res = await api(`/api/users/${userId}`, { method: 'DELETE' });
  const data = await res.json();
  if (res.ok) {
    stepUpToken = null;
    loadUsers();
  } else {
    alert(data.error || 'Delete failed after step-up');
  }
}

// ─── Devices Page ───────────────────────────────────────
async function loadDevices() {
  try {
    // Load pending devices
    const pendingRes = await api('/api/devices/pending');
    if (pendingRes.ok) {
      const { devices: pending } = await pendingRes.json();
      const pendingBody = document.getElementById('pendingDevicesBody');
      if (pending.length === 0) {
        pendingBody.innerHTML = '<tr><td colspan="6" class="text-muted">No pending devices 🎉</td></tr>';
      } else {
        pendingBody.innerHTML = pending.map(d => `
          <tr>
            <td>${d.userId?.email || 'Unknown'}</td>
            <td><code>${d.fingerprint}</code></td>
            <td>${d.browser}</td>
            <td>${d.os}</td>
            <td>${new Date(d.firstSeen).toLocaleString()}</td>
            <td>
              <button onclick="approveDevice('${d._id}')" class="btn btn-sm btn-success">Approve</button>
              ${['admin', 'superadmin'].includes(currentUser?.role) ?
                `<button onclick="blockDevice('${d._id}')" class="btn btn-sm btn-danger">Block</button>` : ''}
            </td>
          </tr>
        `).join('');
      }
    }

    // Load all devices
    const allRes = await api('/api/devices');
    if (allRes.ok) {
      const { devices: all } = await allRes.json();
      const allBody = document.getElementById('allDevicesBody');
      if (all.length === 0) {
        allBody.innerHTML = '<tr><td colspan="8" class="text-muted">No devices registered</td></tr>';
      } else {
        allBody.innerHTML = all.map(d => {
          const statusBadge = d.status === 'TRUSTED' ? 'badge-green' :
                              d.status === 'PENDING' ? 'badge-yellow' : 'badge-red';
          return `
            <tr>
              <td>${d.userId?.email || 'Unknown'}</td>
              <td><code>${d.fingerprint}</code></td>
              <td><span class="badge ${statusBadge}">${d.status}</span></td>
              <td>${d.browser}</td>
              <td>${d.os}</td>
              <td>${new Date(d.lastSeen).toLocaleString()}</td>
              <td>${d.approvedBy?.email || '—'}</td>
              <td>
                ${d.status !== 'TRUSTED' ? `<button onclick="approveDevice('${d._id}')" class="btn btn-sm btn-success">Approve</button>` : ''}
                ${d.status !== 'BLOCKED' && ['admin', 'superadmin'].includes(currentUser?.role) ?
                  `<button onclick="blockDevice('${d._id}')" class="btn btn-sm btn-danger">Block</button>` : ''}
              </td>
            </tr>
          `;
        }).join('');
      }
    }
  } catch (err) {
    console.error('Devices load error:', err);
  }
}

async function approveDevice(deviceId) {
  const res = await api(`/api/devices/${deviceId}/approve`, { method: 'PUT' });
  if (res.ok) {
    loadDevices();
  } else {
    const data = await res.json();
    alert(data.error || 'Failed to approve device');
  }
}

async function blockDevice(deviceId) {
  if (!confirm('Block this device?')) return;
  const res = await api(`/api/devices/${deviceId}/block`, { method: 'PUT' });
  if (res.ok) {
    loadDevices();
  } else {
    const data = await res.json();
    alert(data.error || 'Failed to block device');
  }
}

// ─── Audit Logs Page ────────────────────────────────────
let currentLogPage = 1;

async function loadLogs(page = 1) {
  currentLogPage = page;

  const actor = document.getElementById('logFilterActor').value.trim();
  const action = document.getElementById('logFilterAction').value.trim();
  const decision = document.getElementById('logFilterDecision').value;
  const from = document.getElementById('logFilterFrom').value;
  const to = document.getElementById('logFilterTo').value;

  const params = new URLSearchParams({ page, limit: 30 });
  if (actor) params.set('actor', actor);
  if (action) params.set('action', action);
  if (decision) params.set('decision', decision);
  if (from) params.set('from', from);
  if (to) params.set('to', to);

  try {
    const res = await api(`/api/admin/logs?${params}`);
    if (!res.ok) {
      const err = await res.json();
      document.getElementById('logsTableBody').innerHTML =
        `<tr><td colspan="12" class="error-msg">${err.error}</td></tr>`;
      return;
    }

    const { logs, total, limit } = await res.json();

    document.getElementById('logsMeta').textContent = `Showing page ${page} — ${total} total entries`;

    const tbody = document.getElementById('logsTableBody');
    if (logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="12" class="text-muted">No logs match the filter</td></tr>';
    } else {
      tbody.innerHTML = logs.map(l => {
        const decBadge = l.decision === 'ALLOW' ? 'badge-green' :
                         l.decision === 'DENY' ? 'badge-red' :
                         l.decision === 'STEP_UP' ? 'badge-yellow' : 'badge-gray';
        const riskClass = l.riskLevel === 'HIGH' ? 'risk-high' :
                          l.riskLevel === 'MEDIUM' ? 'risk-medium' : 'risk-low';
        return `
          <tr>
            <td>${new Date(l.timestamp).toLocaleString()}</td>
            <td>${escapeHtml(l.actor)}</td>
            <td>${l.actorRole || '—'}</td>
            <td><strong>${l.action}</strong></td>
            <td>${l.endpoint || '—'}</td>
            <td><span class="badge ${decBadge}">${l.decision}</span></td>
            <td class="${riskClass}">${l.riskScore != null ? l.riskScore : '—'}</td>
            <td>${l.ip || '—'}</td>
            <td>${l.country || '—'}</td>
            <td>${l.browser || '—'}</td>
            <td><code>${l.deviceFingerprint ? l.deviceFingerprint.slice(0, 12) : '—'}</code></td>
            <td>${l.matchedRule || '—'}</td>
          </tr>
        `;
      }).join('');
    }

    // Pagination
    const totalPages = Math.ceil(total / limit);
    const pag = document.getElementById('logsPagination');
    if (totalPages <= 1) {
      pag.innerHTML = '';
    } else {
      let html = '';
      if (page > 1) html += `<button onclick="loadLogs(${page - 1})">← Prev</button>`;
      for (let i = 1; i <= Math.min(totalPages, 10); i++) {
        html += `<button class="${i === page ? 'active' : ''}" onclick="loadLogs(${i})">${i}</button>`;
      }
      if (page < totalPages) html += `<button onclick="loadLogs(${page + 1})">Next →</button>`;
      pag.innerHTML = html;
    }

  } catch (err) {
    console.error('Logs load error:', err);
  }
}

// ─── Policy Page ────────────────────────────────────────
async function loadPolicy() {
  try {
    const res = await api('/api/admin/policy-rules');
    if (!res.ok) {
      const err = await res.json();
      document.getElementById('policyTableBody').innerHTML =
        `<tr><td colspan="4" class="error-msg">${err.error}</td></tr>`;
      return;
    }

    const { rules } = await res.json();
    const tbody = document.getElementById('policyTableBody');
    tbody.innerHTML = rules.map(r => {
      const decBadge = r.decision === 'DENY' ? 'badge-red' :
                       r.decision === 'STEP_UP' ? 'badge-yellow' : 'badge-green';
      return `
        <tr>
          <td><code>${r.id}</code></td>
          <td>${r.description}</td>
          <td><span class="badge ${decBadge}">${r.decision}</span></td>
          <td>${r.reason}</td>
        </tr>
      `;
    }).join('');

  } catch (err) {
    console.error('Policy load error:', err);
  }
}

// ─── Step-Up Auth ───────────────────────────────────────
async function initiateStepUp(callback) {
  stepUpCallback = callback;

  // Request step-up OTP
  const res = await api('/api/auth/step-up', { method: 'POST' });
  if (!res.ok) {
    alert('Failed to initiate step-up authentication');
    return;
  }

  document.getElementById('stepUpModal').classList.remove('hidden');
  document.getElementById('stepUpOtpInput').value = '';
  document.getElementById('stepUpError').classList.add('hidden');
  document.getElementById('stepUpOtpInput').focus();
}

async function handleStepUpVerify(e) {
  e.preventDefault();
  const otp = document.getElementById('stepUpOtpInput').value.trim();
  const errEl = document.getElementById('stepUpError');

  const res = await api('/api/auth/verify-step-up', {
    method: 'POST',
    body: JSON.stringify({ otp })
  });

  const data = await res.json();

  if (!res.ok) {
    errEl.textContent = data.error || 'Verification failed';
    errEl.classList.remove('hidden');
    return;
  }

  stepUpToken = data.stepUpToken;
  closeStepUpModal();

  // Execute the callback that triggered step-up
  if (stepUpCallback) {
    stepUpCallback();
    stepUpCallback = null;
  }
}

function closeStepUpModal() {
  document.getElementById('stepUpModal').classList.add('hidden');
}

/**
 * Show a step-up alert when mid-session IP change or risk spike is detected.
 * Initiates step-up OTP flow automatically.
 */
function showStepUpAlert(reason) {
  const doStepUp = confirm(`🔐 Security Alert!\n\n${reason}\n\nYou need to verify your identity with an OTP. Click OK to receive an OTP.`);
  if (doStepUp) {
    initiateStepUp(() => {
      // After step-up verified, reload the current page data
      alert('✅ Identity verified. You may continue.');
      if (document.getElementById('page-dashboard') && !document.getElementById('page-dashboard').classList.contains('hidden')) {
        loadDashboard();
      }
    });
  } else {
    alert('⚠️ Access will remain restricted until you verify your identity.');
  }
}

// ─── Idle Timeout ───────────────────────────────────────
function startIdleTimer() {
  resetIdleTimer();
  ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach(event => {
    document.addEventListener(event, resetIdleTimer);
  });
}

function resetIdleTimer() {
  document.getElementById('idleWarning').classList.add('hidden');
  clearTimeout(idleTimer);
  clearTimeout(idleWarningTimer);

  // Show warning after IDLE_TIMEOUT
  idleWarningTimer = setTimeout(() => {
    document.getElementById('idleWarning').classList.remove('hidden');
  }, IDLE_TIMEOUT);

  // Auto-logout after IDLE_LOGOUT
  idleTimer = setTimeout(() => {
    logout();
    alert('Session expired due to inactivity.');
  }, IDLE_LOGOUT);
}

function stopIdleTimer() {
  clearTimeout(idleTimer);
  clearTimeout(idleWarningTimer);
  ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach(event => {
    document.removeEventListener(event, resetIdleTimer);
  });
}

// ─── Token Refresh Loop ────────────────────────────────
let refreshInterval = null;

function startTokenRefreshLoop() {
  if (refreshInterval) clearInterval(refreshInterval);
  refreshInterval = setInterval(async () => {
    if (refreshToken) {
      await refreshAccessToken();
    }
  }, TOKEN_REFRESH_INTERVAL);
}

// ─── Utility ────────────────────────────────────────────
function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

// ─── Init ───────────────────────────────────────────────
(function init() {
  loadSession();

  if (accessToken && currentUser) {
    // Try to restore session
    enterApp();
  } else {
    showAuthPage('login');
  }
})();
