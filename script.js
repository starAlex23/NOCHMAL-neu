const BASE = '/api';

// DOM-Elemente
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const showRegisterBtn = document.getElementById('show-register-btn');
const showLoginBtn = document.getElementById('show-login-btn');
const logoutBtn = document.getElementById('logout-btn');
const activateBiometricBtn = document.getElementById('activate-biometric');
const themeSwitcher = document.getElementById('theme-switcher');
const userNameSpan = document.getElementById('user-name');
const vehicleIdSpan = document.getElementById('vehicle-id');
const clockInBtn = document.getElementById('clock-in-btn');
const clockOutBtn = document.getElementById('clock-out-btn');

const qrSection = document.getElementById('qr-section');
const loginSection = document.getElementById('login-section');
const registerSection = document.getElementById('register-section');
const timeTrackingSection = document.getElementById('time-tracking-section');
const qrReaderElem = document.getElementById('qr-reader');
const qrMessage = document.getElementById('qr-message');
const loginEmail = document.getElementById('login-email');
const loginPassword = document.getElementById('login-password');
const loginError = document.getElementById('login-error');
// API-Endpunkt (Render-Backend)
const API_BASE = 'https://zeiterfassung-backend.onrender.com';


let html5QrCode = null;
let scannedVehicleId = null;
let loggedInUser = null;
let biometricEnabled = false;

// === Hilfsfunktion: CSRF aus Cookie lesen ===
function getCsrfTokenFromCookie() {
  const match = document.cookie.match(/(^|;\s*)csrf=([^;]+)/);
  return match ? decodeURIComponent(match[2]) : null;
}

// === Fetch Wrapper mit CSRF und Auto-Refresh ===
async function apiFetch(url, options = {}, useAuthHeaderToken = false, authToken = null) {
  const csrfToken = getCsrfTokenFromCookie();
  if (!options.headers) options.headers = {};
  if (csrfToken) options.headers['X-CSRF-Token'] = csrfToken;

  options.credentials = 'include';

  if (useAuthHeaderToken && authToken) {
    options.headers['Authorization'] = 'Bearer ' + authToken;
  }

  let res = await fetch(API_BASE + url, options);

  if (res.status === 401 && url !== '/token/refresh') {
    const refreshed = await tryTokenRefresh();
    if (refreshed) {
      res = await fetch(API_BASE + url, options);
      if (res.status === 401) {
        handleLogoutCleanup();
        throw new Error('Nicht eingeloggt (nach Refresh)');
      }
    } else {
      handleLogoutCleanup();
      throw new Error('Nicht eingeloggt (kein Refresh möglich)');
    }
  }

  return res;
}


async function tryTokenRefresh() {
  try {
    const res = await fetch(API_BASE + '/token/refresh', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'X-CSRF-Token': getCsrfTokenFromCookie() || '',
      },
    });
    return res.ok;
  } catch {
    return false;
  }
}

// === Theme Handling ===
function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  themeSwitcher.textContent = theme === 'dark' ? '☀️' : '🌙';
  localStorage.setItem('theme', theme);
}
function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  setTheme(current === 'dark' ? 'light' : 'dark');
}
(() => {
  const saved = localStorage.getItem('theme');
  if (saved) setTheme(saved);
  else {
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    setTheme(prefersDark ? 'dark' : 'light');
  }
})();
themeSwitcher.addEventListener('click', toggleTheme);

// === Sections anzeigen ===
function showSection(section) {
  [qrSection, loginSection, registerSection, timeTrackingSection].forEach(s => {
    s.classList.add('hidden');
    s.setAttribute('aria-hidden', 'true');
  });
  section.classList.remove('hidden');
  section.setAttribute('aria-hidden', 'false');
}

// === QR Scanner ===
async function startQrScanner() {
  qrMessage.textContent = "Scanne den QR-Code";
  if (!html5QrCode) html5QrCode = new Html5Qrcode("qr-reader");

  try {
    await html5QrCode.start(
      { facingMode: "environment" },
      { fps: 10, qrbox: 250 },
      async (text) => {
        const qrCode = text.trim();
        qrMessage.textContent = "QR-Code erkannt: " + qrCode;
        try {
          await validateQrCode(qrCode);
          scannedVehicleId = qrCode;
          await stopQrScanner();
          // Versuche automatischen Login
          const autoLoggedIn = await tryAutoLogin();
          if (!autoLoggedIn) showSection(loginSection);
        } catch (err) {
          qrMessage.textContent = "Ungültiger QR-Code";
          console.error(err);
        }
      }
    );
  } catch (err) {
    qrMessage.textContent = "Kamera nicht verfügbar.";
    console.error(err);
  }
}
async function stopQrScanner() {
  try {
    await html5QrCode?.stop();
  } catch (e) {
    console.warn("Fehler beim Stoppen des QR-Scanners:", e);
  }
  qrReaderElem.innerHTML = "";
}

// QR-Code Validierung gegen Backend
async function validateQrCode(qr) {
  const res = await apiFetch('/validate-qr', {
    method: 'POST',
    body: JSON.stringify({ qr }),
    headers: { 'Content-Type': 'application/json' },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Ungültiger QR-Code');
  }
}

// === Auth ===

// Login mit Email/Passwort
async function login(email, password) {
  const res = await apiFetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || 'Login fehlgeschlagen');
  }

  const userRes = await apiFetch('/me');
  if (!userRes.ok) throw new Error('Fehler beim Abrufen der Benutzerdaten nach Login');
  return userRes.json();
}


// WebAuthn Registrierung starten
async function startWebAuthnRegistration() {
  try {
    const resp = await apiFetch('/webauthn/register-request', {
      method: 'POST',
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.error || 'WebAuthn Registrierung Anfrage fehlgeschlagen');
    }
    const options = await resp.json();

    // Challenge und IDs in Uint8Array konvertieren
    options.challenge = base64urlToUint8Array(options.challenge);
    options.user.id = base64urlToUint8Array(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map(cred => ({
        ...cred,
        id: base64urlToUint8Array(cred.id),
      }));
    }

    const credential = await navigator.credentials.create({ publicKey: options });

    const credentialResponse = {
      id: credential.id,
      rawId: toBase64Url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: toBase64Url(credential.response.attestationObject),
        clientDataJSON: toBase64Url(credential.response.clientDataJSON),
      },
    };

    const verifyResp = await apiFetch('/webauthn/register-response', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentialResponse),
    });

    if (!verifyResp.ok) {
      const err = await verifyResp.json().catch(() => ({}));
      throw new Error(err.error || 'WebAuthn Registrierung fehlgeschlagen');
    }

    return true;
  } catch (err) {
    console.error(err);
    throw err;
  }
}



// WebAuthn Login Anfrage + Antwort
async function loginViaWebAuthn(email) {
  try {
    const res = await apiFetch('/webauthn/login-request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'WebAuthn Login-Anfrage fehlgeschlagen');
    }
    const options = await res.json();

    options.challenge = base64urlToUint8Array(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map(cred => ({
        ...cred,
        id: base64urlToUint8Array(cred.id),
      }));
    }

    const assertion = await navigator.credentials.get({ publicKey: options });

    const credential = {
      id: assertion.id,
      rawId: toBase64Url(assertion.rawId),
      type: assertion.type,
      response: {
        authenticatorData: toBase64Url(assertion.response.authenticatorData),
        clientDataJSON: toBase64Url(assertion.response.clientDataJSON),
        signature: toBase64Url(assertion.response.signature),
        userHandle: assertion.response.userHandle ? toBase64Url(assertion.response.userHandle) : null,
      },
    };

    const verifyResp = await apiFetch('/webauthn/login-response', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential }),
    });
    if (!verifyResp.ok) {
      const err = await verifyResp.json().catch(() => ({}));
      throw new Error(err.error || 'WebAuthn Login fehlgeschlagen');
    }

    const userRes = await apiFetch('/me');
    if (!userRes.ok) throw new Error('Fehler beim Abrufen der Benutzerdaten nach WebAuthn Login');
    return userRes.json();
  } catch (err) {
    console.error(err);
    throw err;
  }
}


async function checkBiometricStatus() {
  try {
   const response = await fetch(API_BASE + '/api/user/biometric-status', {
      method: 'GET',
      credentials: 'include', // sendet Cookies mit
      headers: {
        'Accept': 'application/json',
        // Falls du Token im Header brauchst:
        // 'Authorization': 'Bearer ' + deinToken,
        // 'X-CSRF-Token': deinCSRFToken // falls CSRF-Schutz aktiv
      }
    });

    if (!response.ok) {
      throw new Error(`Fehler: ${response.status}`);
    }

    const data = await response.json();
    console.log('WebAuthn aktiv?', data.biometricEnabled);
    return data.biometricEnabled; // true oder false
  } catch (err) {
    console.error('Fehler beim Abrufen des Biometrie-Status:', err);
    return false;
  }
}


// === Helper Funktionen zur Base64-URL-Konvertierung (für WebAuthn) ===
function base64urlToUint8Array(base64urlString) {
  const padding = '='.repeat((4 - (base64urlString.length % 4)) % 4);
  const base64 = (base64urlString + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

function toBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// === Automatischer Login (z.B. nach QR-Scan) ===
async function tryAutoLogin() {
  try {
    // Prüfe, ob bereits eingeloggt (Session oder Token)
    const res = await apiFetch('/me');
    if (res.ok) {
      loggedInUser = await res.json();
      biometricEnabled = loggedInUser.biometricEnabled || false;
      updateUIAfterLogin();
      return true;
    }

    // Wenn nicht, prüfe, ob WebAuthn aktiviert ist und starte WebAuthn Login (z.B. durch gespeicherte Credentials)
    if (biometricEnabled && loginEmail.value) {
      loggedInUser = await loginViaWebAuthn(loginEmail.value);
      updateUIAfterLogin();
      return true;
    }

    return false;
  } catch (err) {
    console.warn('AutoLogin fehlgeschlagen:', err);
    return false;
  }
}

// === UI Aktualisierung nach Login ===
function updateUIAfterLogin() {
  userNameSpan.textContent = loggedInUser.name || loggedInUser.email || 'Benutzer';
  vehicleIdSpan.textContent = scannedVehicleId || '-';
  showSection(timeTrackingSection);
  loginSection.classList.add('hidden');
  registerSection.classList.add('hidden');
  qrSection.classList.add('hidden');
  logoutBtn.classList.remove('hidden');
  activateBiometricBtn.classList.toggle('hidden', biometricEnabled);
}

async function updateTimeButtons() {
  const res = await apiFetch('/zeit/status');
  if (!res.ok) return;
  const data = await res.json();
  clockInBtn.disabled = data.status === 'running';
  clockOutBtn.disabled = data.status !== 'running';
}

// === Logout Cleanup ===
function handleLogoutCleanup() {
  loggedInUser = null;
  scannedVehicleId = null;
  biometricEnabled = false;
  loginEmail.value = '';
  loginPassword.value = '';
  showSection(qrSection);
  logoutBtn.classList.add('hidden');
  activateBiometricBtn.classList.remove('hidden');
  userNameSpan.textContent = '';
  vehicleIdSpan.textContent = '';
}

// === Logout ===
logoutBtn.addEventListener('click', async () => {
  try {
    const res = await apiFetch('/logout', { method: 'POST' });
    if (res.ok) {
      handleLogoutCleanup();
    } else {
      alert('Logout fehlgeschlagen');
    }
  } catch (err) {
    console.error(err);
    alert('Logout Fehler');
  }
});

// === Login-Formular ===
loginForm.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  loginError.textContent = '';
  try {
    loggedInUser = await login(loginEmail.value.trim(), loginPassword.value);
    biometricEnabled = loggedInUser.biometricEnabled || false;
    updateUIAfterLogin();
  } catch (err) {
    loginError.textContent = err.message;
  }
});

// === Register-Link im Login-Form ===
showRegisterBtn.addEventListener('click', () => {
  showSection(registerSection);
});

// === Zurück zum Login ===
showLoginBtn.addEventListener('click', () => {
  showSection(loginSection);
});

// === Registrierung ===
registerForm.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const email = registerForm['email'].value.trim();
  const password = registerForm['password'].value.trim();
  try {
    const res = await apiFetch('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Registrierung fehlgeschlagen');
    }
    alert('Registrierung erfolgreich! Bitte einloggen.');
    showSection(loginSection);
  } catch (err) {
    alert(err.message);
  }
});

// === WebAuthn Aktivierung Button ===
activateBiometricBtn.addEventListener('click', async () => {
  activateBiometricBtn.disabled = true;
  try {
    await startWebAuthnRegistration();
    alert('Biometrische Anmeldung aktiviert!');
    biometricEnabled = true;
    activateBiometricBtn.classList.add('hidden');
  } catch (err) {
    alert('WebAuthn Registrierung fehlgeschlagen: ' + err.message);
  } finally {
    activateBiometricBtn.disabled = false;
  }
});


// === Zeit erfassen (Start) ===
clockInBtn.addEventListener('click', async () => {
  if (!loggedInUser) {
    alert('Bitte zuerst einloggen');
    return;
  }

  try {
    const res = await apiFetch('/zeit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ aktion: 'start' }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Start der Zeitbuchung fehlgeschlagen');
    }

    alert('Arbeitszeit gestartet');
  } catch (err) {
    console.error(err);
    alert('Fehler beim Start der Arbeitszeit: ' + err.message);
  }
});


// === Zeit erfassen (Stopp) ===
clockOutBtn.addEventListener('click', async () => {
  if (!loggedInUser) {
    alert('Bitte zuerst einloggen');
    return;
  }

  clockOutBtn.disabled = true;

  try {
    const res = await apiFetch('/zeit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ aktion: 'stop' }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Stop der Zeitbuchung fehlgeschlagen');
    }

    alert('Arbeitszeit gestoppt');
  } catch (err) {
    console.error('Fehler beim Stop:', err);
    alert('Fehler beim Stoppen der Arbeitszeit: ' + err.message);
  } finally {
    clockOutBtn.disabled = false;
  }
});


//schon eingestempelt?
async function getLetzterStatus() {
  try {
    const response = await fetch(API_BASE + '/api/zeit/letzter-status', {
      method: 'GET',
      credentials: 'include',
      headers: {
        'Accept': 'application/json',
        // 'Authorization': 'Bearer ' + deinToken,
        // 'X-CSRF-Token': deinCSRFToken
      }
    });

    if (!response.ok) {
      throw new Error(`Fehler: ${response.status}`);
    }

    const data = await response.json();
    console.log('Letzter Zeitstatus:', data);
    return data; // z.B. { aktion: 'start', zeit: '2025-06-09T08:00:00Z' }
  } catch (err) {
    console.error('Fehler beim Abrufen des letzten Status:', err);
    return null;
  }
}


// === Initial Setup ===
async function init() {
  showSection(qrSection);
  await startQrScanner();
  await tryAutoLogin();
}
init();

async function fetchUserProfile() {
  const response = await apiFetch('/me');
  if (!response.ok) throw new Error('Benutzerdaten konnten nicht geladen werden');
  const user = await response.json();
  return user;
}

