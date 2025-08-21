const API = "/api";
let token = null;

const loginSection = document.getElementById("login-section");
const rulesSection = document.getElementById("rules-section");
const userInfo = document.getElementById("user-info");
const loginForm = document.getElementById("login-form");
const loginError = document.getElementById("login-error");
const searchInput = document.getElementById("search");
const refreshBtn = document.getElementById("refresh");
const logoutBtn = document.getElementById("logout");
const rulesTableBody = document.querySelector("#rules-table tbody");
const rulesError = document.getElementById("rules-error");

function showLogged(username) {
  userInfo.textContent = `Logged as ${username}`;
  loginSection.classList.add("hidden");
  rulesSection.classList.remove("hidden");
}

function logout() {
  token = null;
  userInfo.textContent = "";
  rulesTableBody.innerHTML = "";
  loginSection.classList.remove("hidden");
  rulesSection.classList.add("hidden");
  localStorage.removeItem("jwt");
  localStorage.removeItem("user");
}

async function apiFetch(path, options = {}) {
  const headers = options.headers || {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`${API}${path}`, { ...options, headers });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.detail?.message || JSON.stringify(detail));
  }
  return res.json();
}

async function loadRules() {
  rulesError.textContent = "";
  rulesTableBody.innerHTML = "";
  const search = encodeURIComponent(searchInput.value || "");
  const data = await apiFetch(`/rules?search=${search}`);
  (data.rows || []).forEach(r => {
    const tr = document.createElement("tr");
    const enabled = (r.enable === "1" || r.enabled === "1" || r.enable === 1 || r.enabled === true);
    tr.innerHTML = `
      <td>${r.uuid || ""}</td>
      <td>${r.description || ""}</td>
      <td>${r.interface || ""}</td>
      <td>${r.action || ""}</td>
      <td>${enabled ? "yes" : "no"}</td>
      <td><button data-uuid="${r.uuid}">toggle</button></td>
    `;
    tr.querySelector("button").onclick = async (e) => {
      try {
        await apiFetch(`/rules/${e.target.dataset.uuid}/toggle`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: null, apply: true }),
        });
        await loadRules();
      } catch (err) {
        rulesError.textContent = err.message;
      }
    };
    rulesTableBody.appendChild(tr);
  });
}

loginForm.onsubmit = async (e) => {
  e.preventDefault();
  loginError.textContent = "";
  const form = new FormData(loginForm);
  const username = form.get("username");
  const password = form.get("password");
  try {
    const data = await fetch(`${API}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    }).then(r => r.json());
    if (!data.access_token) throw new Error("Login failed");
    token = data.access_token;
    localStorage.setItem("jwt", token);
    localStorage.setItem("user", username);
    showLogged(username);
    await loadRules();
  } catch (err) {
    loginError.textContent = "Invalid credentials.";
  }
};

refreshBtn.onclick = loadRules;
logoutBtn.onclick = logout;

// auto-login se presente
(function init() {
  const saved = localStorage.getItem("jwt");
  const user = localStorage.getItem("user");
  if (saved) {
    token = saved;
    showLogged(user || "user");
    loadRules().catch(e => (rulesError.textContent = e.message));
  }
})();