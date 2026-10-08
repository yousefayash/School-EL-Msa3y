const LOGIN_KEY = "masai_admin_login";

const isAdmin = () => sessionStorage.getItem(LOGIN_KEY) === "1";

function updateAdminNav() {
  const link = document.querySelector("#adminNav");
  if (!link) return;
  if (isAdmin()) {
    link.textContent = "إدارة المدرسة";
    link.href = "admin.html";
  } else {
    link.textContent = "Admin Login";
    link.href = "admin.html";
  }
}

function setupMobileMenu() {
  const toggle = document.querySelector(".menu-toggle");
  const nav = document.querySelector(".links");
  if (toggle && nav) toggle.addEventListener("click", () => nav.classList.toggle("open"));
}

function setupRegistration() {
  const form = document.querySelector("#registrationForm");
  if (!form) return;
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const button = form.querySelector("button[type='submit']");
    const original = button?.textContent || "إرسال طلب التسجيل";
    if (button) { button.disabled = true; button.textContent = "جارٍ الإرسال..."; }
    try {
      const data = Object.fromEntries(new FormData(form));
      const response = await fetch("/api/registrations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "تعذر إرسال الطلب");
      form.reset();
      const toast = document.querySelector("#toast");
      if (toast) {
        toast.textContent = "تم إرسال طلب التسجيل بنجاح";
        toast.style.display = "block";
        setTimeout(() => toast.style.display = "none", 2800);
      }
    } catch (error) {
      alert(error.message || "تعذر الاتصال بالخادم");
    } finally {
      if (button) { button.disabled = false; button.textContent = original; }
    }
  });
}

async function setupAdminLogin() {
  const form = document.querySelector("#adminLogin");
  if (!form) return;
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const username = document.querySelector("#username").value.trim();
    const password = document.querySelector("#password").value;
    const error = document.querySelector("#loginError");
    error.textContent = "";
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "فشل تسجيل الدخول");
      sessionStorage.setItem(LOGIN_KEY, "1");
      location.href = "admin.html";
    } catch (e) {
      error.textContent = e.message;
    }
  });
}

async function initAdmin() {
  const loginView = document.querySelector("#loginView");
  const dashView = document.querySelector("#dashView");
  if (!loginView || !dashView) return;
  try {
    const response = await fetch("/api/auth/me");
    if (!response.ok) throw new Error("not-authenticated");
    sessionStorage.setItem(LOGIN_KEY, "1");
    loginView.style.display = "none";
    dashView.style.display = "block";
    await renderDashboard();
  } catch {
    sessionStorage.removeItem(LOGIN_KEY);
    loginView.style.display = "block";
    dashView.style.display = "none";
  }
  updateAdminNav();
}

async function renderDashboard() {
  const [statsResponse, registrationsResponse] = await Promise.all([
    fetch("/api/admin/stats"),
    fetch("/api/admin/registrations")
  ]);
  if (statsResponse.status === 401 || registrationsResponse.status === 401) {
    sessionStorage.removeItem(LOGIN_KEY);
    location.href = "admin.html";
    return;
  }
  const stats = await statsResponse.json();
  const payload = await registrationsResponse.json();
  const records = payload.registrations || [];
  const total = document.querySelector("#total");
  const today = document.querySelector("#today");
  const table = document.querySelector("#tableBody");
  if (total) total.textContent = stats.total ?? records.length;
  if (today) today.textContent = stats.today ?? 0;
  if (!table) return;
  table.innerHTML = records.length ? records.map(x => `
    <tr>
      <td>${escapeHtml(x.name || "-")}</td>
      <td>${escapeHtml(x.grade || "-")}</td>
      <td>${escapeHtml(x.phone || "-")}</td>
      <td>${escapeHtml(x.email || "-")}</td>
      <td>${escapeHtml(formatDate(x.date))}</td>
      <td>${escapeHtml(x.status || "جديد")}</td>
    </tr>`).join("") : `<tr><td colspan="6">لا توجد طلبات تسجيل حتى الآن.</td></tr>`;
}

function formatDate(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString("ar-EG");
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#039;"}[char]));
}

async function logout() {
  try { await fetch("/api/auth/logout", { method: "POST" }); } catch {}
  sessionStorage.removeItem(LOGIN_KEY);
  location.href = "admin.html";
}

async function clearRegs() {
  if (!confirm("هل تريد حذف كل طلبات التسجيل من قاعدة البيانات؟")) return;
  const response = await fetch("/api/admin/registrations", { method: "DELETE" });
  if (response.ok) await renderDashboard();
}

window.logout = logout;
window.clearRegs = clearRegs;

document.addEventListener("DOMContentLoaded", () => {
  updateAdminNav();
  setupMobileMenu();
  setupRegistration();
  setupAdminLogin();
  initAdmin();
  document.querySelectorAll(".card,.feature-card,.news-card,.gallery-item,.timeline>div,.steps>div").forEach((el, i) => {
    el.classList.add("reveal");
    el.style.animationDelay = `${Math.min(i * 60, 360)}ms`;
  });
});
