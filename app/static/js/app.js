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

function scoreColor(score) {
  return score >= 80 ? "green" : score >= 50 ? "yellow" : "red";
}

const RING_CIRCUMFERENCE = 326.7;

function updateHeroPreview(result) {
  const ring = document.getElementById("hero-score-ring");
  const num = document.getElementById("hero-score-num");
  const list = document.getElementById("hero-preview-list");
  if (!ring || !num || !list) return;

  const score = result.overall_score;
  const color = scoreColor(score);
  num.textContent = score;
  ring.style.strokeDashoffset = RING_CIRCUMFERENCE * (1 - score / 100);
  ring.classList.remove("green", "yellow", "red");
  ring.classList.add(color);

  list.innerHTML = result.categories
    .map((cat) => `<li><span class="dot ${statusColor(cat.status)}"></span> ${cat.label}</li>`)
    .join("");
}

const LOADING_STEP_MS = 1100;
const MIN_LOADING_MS = 4200; // damit die Fortschrittsanzeige bei sehr schnellen Scans sichtbar bleibt
let loadingTimer = null;

function waitForMinDuration(startedAt) {
  const elapsed = Date.now() - startedAt;
  const remaining = MIN_LOADING_MS - elapsed;
  if (remaining <= 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, remaining));
}

function startLoadingAnimation() {
  const items = Array.from(document.querySelectorAll("#loading-steps li"));
  if (!items.length) return;
  stopLoadingAnimation();
  let i = 0;
  const tick = () => {
    items.forEach((el, idx) => {
      el.classList.toggle("done", idx < i);
      el.classList.toggle("active", idx === i);
    });
    i = (i + 1) % items.length;
  };
  tick();
  loadingTimer = setInterval(tick, LOADING_STEP_MS);
}

function stopLoadingAnimation() {
  if (loadingTimer) {
    clearInterval(loadingTimer);
    loadingTimer = null;
  }
  document.querySelectorAll("#loading-steps li").forEach((el) => el.classList.remove("active"));
}

function renderReport(result) {
  stopLoadingAnimation();
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

  const reportRingColor = scoreColor(result.overall_score);
  const reportRingOffset = RING_CIRCUMFERENCE * (1 - result.overall_score / 100);

  const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const allIssues = result.categories
    .flatMap((cat) =>
      cat.findings
        .filter((f) => f.severity !== "info")
        .map((f) => ({ ...f, categoryLabel: cat.label }))
    )
    .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);

  const issuesHtml = allIssues.length
    ? allIssues
        .map(
          (f) => `
        <li class="finding">
          <span class="sev-badge sev-${f.severity}">${severityLabel(f.severity)}</span>
          <span class="finding-body"><strong>${f.title}</strong><span class="finding-category">${f.categoryLabel}</span>${f.detail}</span>
        </li>`
        )
        .join("")
    : `<li class="finding"><span class="sev-badge sev-info">Info</span><span class="finding-body"><strong>Keine offenen Punkte gefunden</strong>Alle geprüften Bereiche sind unauffällig.</span></li>`;

  reportContent.innerHTML = `
    ${notice}
    <div class="report-header">
      <h2>Compliance Report</h2>
      <div class="url">${result.url}</div>
      <div class="report-ring">
        <svg viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="52" class="ring-bg" />
          <circle cx="60" cy="60" r="52" class="ring-fg ${reportRingColor}" style="stroke-dashoffset:${reportRingOffset}" />
        </svg>
        <div class="report-ring-num">${result.overall_score}</div>
      </div>
      <div class="overall-score">
        <div class="risk ${riskClass(result.overall_score)}">${result.risk_label}</div>
      </div>
    </div>
    <div class="category-grid">${categoriesHtml}</div>
    <div class="issue-summary">
      <h2>Alle offenen Punkte auf einen Blick (${allIssues.length})</h2>
      <p class="issue-summary-sub">Genau das musst du auf deiner Seite anpassen, sortiert nach Dringlichkeit.</p>
      <ul class="findings-list issue-summary-list">${issuesHtml}</ul>
    </div>
  `;

  reportContent.scrollIntoView({ behavior: "smooth", block: "start" });
}

function showLoading() {
  reportSection.hidden = false;
  reportLoading.hidden = false;
  reportError.hidden = true;
  reportContent.hidden = true;
  reportSection.scrollIntoView({ behavior: "smooth", block: "start" });
  startLoadingAnimation();
}

function showReportError(msg) {
  stopLoadingAnimation();
  reportSection.hidden = false;
  reportLoading.hidden = true;
  reportContent.hidden = true;
  reportError.hidden = false;
  reportError.textContent = msg;
}

async function pollScanResult(sessionId) {
  showLoading();
  const started = Date.now();
  try {
    const resp = await fetch(`/api/scan/result?session_id=${encodeURIComponent(sessionId)}`);
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.detail || "Zahlung konnte nicht verifiziert werden.");
    }
    const result = await resp.json();
    await waitForMinDuration(started);
    renderReport(result);
  } catch (e) {
    showReportError(e.message || "Unbekannter Fehler beim Laden des Reports.");
  }
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  errBox.hidden = true;

  const url = document.getElementById("store-url").value.trim();

  if (!url) {
    showError("Bitte gib die URL deines Shops ein.");
    return;
  }

  const originalBtnText = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Wird geprüft...";
  const scanStarted = Date.now();
  showLoading();

  try {
    const resp = await fetch("/api/start-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
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
      await waitForMinDuration(scanStarted);
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
