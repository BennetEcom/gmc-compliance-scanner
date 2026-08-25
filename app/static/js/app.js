document.getElementById("year").textContent = new Date().getFullYear();

const form = document.getElementById("scan-form");
const btn = document.getElementById("scan-btn");
const errBox = document.getElementById("form-error");

const reportSection = document.getElementById("report-section");
const reportLoading = document.getElementById("report-loading");
const reportError = document.getElementById("report-error");
const reportContent = document.getElementById("report-content");

function showError(msg) {
  errBox.textContent = msg;
  errBox.hidden = false;
}

function severityLabel(sev) {
  return { critical: "Kritisch", high: "Hoch", medium: "Mittel", low: "Niedrig", info: "Info" }[sev] || sev;
}

function statusColor(status) {
  return { green: "green", yellow: "yellow", red: "red" }[status] || "yellow";
}

function riskClass(score) {
  if (score >= 80) return "risk-green";
  if (score >= 50) return "risk-yellow";
  return "risk-red";
}

const RING_CIRCUMFERENCE = 326.7;

function updateHeroPreview(result) {
  const ring = document.getElementById("hero-score-ring");
  const num = document.getElementById("hero-score-num");
  const list = document.getElementById("hero-preview-list");
  if (!ring || !num || !list) return;

  const score = result.overall_score;
  const color = score >= 80 ? "green" : score >= 50 ? "yellow" : "red";
  num.textContent = score;
  ring.style.strokeDashoffset = RING_CIRCUMFERENCE * (1 - score / 100);
  ring.classList.remove("green", "yellow", "red");
  ring.classList.add(color);

  list.innerHTML = result.categories
    .map((cat) => `<li><span class="dot ${statusColor(cat.status)}"></span> ${cat.label}</li>`)
    .join("");
}

function renderReport(result) {
  updateHeroPreview(result);
  reportSection.hidden = false;
  reportLoading.hidden = true;
  reportError.hidden = true;
  reportContent.hidden = false;

  const notice = result._notice
    ? `<div class="notice-banner">${result._notice}</div>`
    : "";

  const categoriesHtml = result.categories
    .map((cat) => {
      const color = statusColor(cat.status);
      const findingsHtml = cat.findings
        .map(
          (f) => `
        <li class="finding">
          <span class="sev-badge sev-${f.severity}">${severityLabel(f.severity)}</span>
          <span class="finding-body"><strong>${f.title}</strong>${f.detail}</span>
        </li>`
        )
        .join("");
      return `
      <div class="category-card">
        <div class="category-card-header">
          <div class="category-title"><span class="dot ${color}"></span> ${cat.label}</div>
          <div class="category-score">${cat.score}/100</div>
        </div>
        <div class="bar-track"><div class="bar-fill ${color}" style="width:${cat.score}%"></div></div>
        <ul class="findings-list">${findingsHtml}</ul>
      </div>`;
    })
    .join("");

  reportContent.innerHTML = `
    ${notice}
    <div class="report-header">
      <div>
        <h2>Compliance Report</h2>
        <div class="url">${result.url}</div>
      </div>
      <div class="overall-score">
        <div class="num">${result.overall_score}</div>
        <div class="risk ${riskClass(result.overall_score)}">${result.risk_label}</div>
      </div>
    </div>
    <div class="category-grid">${categoriesHtml}</div>
  `;

  reportContent.scrollIntoView({ behavior: "smooth", block: "start" });
}

function showLoading() {
  reportSection.hidden = false;
  reportLoading.hidden = false;
  reportError.hidden = true;
  reportContent.hidden = true;
  reportSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

function showReportError(msg) {
  reportSection.hidden = false;
  reportLoading.hidden = true;
  reportContent.hidden = true;
  reportError.hidden = false;
  reportError.textContent = msg;
}

async function pollScanResult(sessionId) {
  showLoading();
  try {
    const resp = await fetch(`/api/scan/result?session_id=${encodeURIComponent(sessionId)}`);
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.detail || "Zahlung konnte nicht verifiziert werden.");
    }
    const result = await resp.json();
    renderReport(result);
  } catch (e) {
    showReportError(e.message || "Unbekannter Fehler beim Laden des Reports.");
  }
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  errBox.hidden = true;

  const url = document.getElementById("store-url").value.trim();
  const promo = document.getElementById("promo-code").value.trim();

  if (!url) {
    showError("Bitte gib die URL deines Shops ein.");
    return;
  }

  const originalBtnText = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Wird geprüft...";

  try {
    const resp = await fetch("/api/start-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, promo_owner_code: promo || null }),
    });

    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.detail || "Fehler beim Starten des Scans.");
    }

    const data = await resp.json();

    if (data.mode === "redirect") {
      window.location.href = data.checkout_url;
      return;
    }

    if (data.mode === "direct") {
      renderReport(data.result);
    }
  } catch (e) {
    showError(e.message || "Unbekannter Fehler.");
  } finally {
    btn.disabled = false;
    btn.textContent = originalBtnText;
  }
});

// Falls wir von Stripe zurückkommen (?session_id=...), Report laden.
if (window.__PENDING_SESSION_ID__) {
  pollScanResult(window.__PENDING_SESSION_ID__);
}
