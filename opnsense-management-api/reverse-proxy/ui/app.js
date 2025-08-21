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
        throw new Error(detail.message || detail.detail?.message || JSON.stringify(detail));
    }
    return res.json();
}

async function loadRules() {
    try {
        rulesError.textContent = "";
        rulesTableBody.innerHTML = "";
        
        const search = encodeURIComponent(searchInput.value || "");
        const data = await apiFetch(`/rules?search=${search}`);
        
        (data.data || []).forEach(rule => {
            const tr = document.createElement("tr");
            const enabled = rule.enabled === true || rule.enabled === 1 || rule.enabled === "1";
            
            tr.innerHTML = `
                <td>${rule.id || ""}</td>
                <td>${rule.description || ""}</td>
                <td>${rule.interface || ""}</td>
                <td>${rule.action || ""}</td>
                <td>${enabled ? "✅ Yes" : "❌ No"}</td>
                <td><button data-id="${rule.id}" data-enabled="${enabled}">
                    ${enabled ? "Disable" : "Enable"}
                </button></td>
            `;
            
            const toggleBtn = tr.querySelector("button");
            toggleBtn.onclick = async (e) => {
                try {
                    const ruleId = e.target.dataset.id;
                    const currentEnabled = e.target.dataset.enabled === "true";
                    const newEnabled = !currentEnabled;
                    
                    rulesError.textContent = "";
                    e.target.disabled = true;
                    e.target.textContent = "...";
                    
                    await apiFetch(`/rules/${ruleId}/toggle`, {
                        method: "PATCH",  // Corretto!
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ enabled: newEnabled })  // Payload corretto!
                    });
                    
                    await loadRules();
                } catch (err) {
                    rulesError.textContent = `Toggle error: ${err.message}`;
                    e.target.disabled = false;
                    e.target.textContent = currentEnabled ? "Disable" : "Enable";
                }
            };
            
            rulesTableBody.appendChild(tr);
        });
    } catch (err) {
        rulesError.textContent = `Load error: ${err.message}`;
    }
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

// Auto-login se presente
(function init() {
    const saved = localStorage.getItem("jwt");
    const user = localStorage.getItem("user");
    if (saved) {
        token = saved;
        showLogged(user || "user");
        loadRules().catch(e => {
            rulesError.textContent = e.message;
        });
    }
})();