const API_BASE = 'http://localhost:3000/api';
const SESSION_TOKEN = 'techstore_token';
const TEMP_TOKEN = 'techstore_token_temporal';

function getToken() { return sessionStorage.getItem(SESSION_TOKEN); }
function getTemporaryToken() { return sessionStorage.getItem(TEMP_TOKEN); }
function saveToken(token) { sessionStorage.setItem(SESSION_TOKEN, token); sessionStorage.removeItem(TEMP_TOKEN); }
function saveTemporaryToken(token) { sessionStorage.removeItem(SESSION_TOKEN); sessionStorage.setItem(TEMP_TOKEN, token); }
function clearSession() { sessionStorage.removeItem(SESSION_TOKEN); sessionStorage.removeItem(TEMP_TOKEN); sessionStorage.removeItem('techstore_user'); }
function getStoredUser() { try { return JSON.parse(sessionStorage.getItem('techstore_user') || 'null'); } catch { return null; } }
function saveUser(user) { if (user) sessionStorage.setItem('techstore_user', JSON.stringify(user)); }
function requireAuth() { if (!getToken()) { window.location.href = 'login.html'; return false; } return true; }
function redirectIfAuthenticated() { if (getToken()) window.location.href = 'dashboard.html'; }
async function apiFetch(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (options.auth !== false && getToken()) headers.Authorization = `Bearer ${getToken()}`;
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  let data = {}; try { data = await response.json(); } catch { data = { mensaje: 'Respuesta no válida del servidor' }; }
  if (response.status === 401 && options.auth !== false) { clearSession(); window.location.href = 'login.html'; }
  if (!response.ok) { const error = new Error(data.mensaje || 'No se pudo completar la solicitud'); error.data = data; error.status = response.status; throw error; }
  return data;
}
function showAlert(target, message, type = 'danger') { const el = typeof target === 'string' ? document.querySelector(target) : target; if (el) el.innerHTML = `<div class="alert alert-${type} py-2 small" role="alert"><i class="bi bi-${type === 'success' ? 'check-circle' : 'exclamation-circle'} me-2"></i>${message}</div>`; }
function setLoading(button, loading) { if (!button) return; button.disabled = loading; button.querySelector('.button-label')?.classList.toggle('d-none', loading); button.querySelector('.spinner-border')?.classList.toggle('d-none', !loading); }
