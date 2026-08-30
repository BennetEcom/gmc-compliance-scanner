document.getElementById("year").textContent = new Date().getFullYear();
applyLang(getLang());

document.querySelectorAll("[data-lang-btn]").forEach((btn) => {
  btn.addEventListener("click", () => setLang(btn.getAttribute("data-lang-btn")));
});

document.addEventListener("click", (e) => {
  const box = e.target.closest(".checklist-box");
  if (!box) return;
  box.classList.toggle("checked");
  box.closest(".checklist-item")?.classList.toggle("done");
});

const form = document.getElementById("scan-form");
const btn = document.getElementById("scan-btn");
const errBox = document.getElementById("form-error");
const packageNotice = document.getElementById("package-notice");

const reportSection = document.getElementById("report-section");
const reportLoading = document.getElementById("report-loading");
const reportError = document.getElementById("report-error");
const reportContent = document.getElementById("report-content");

function showError(msg) {
  errBox.textContent = msg;
  errBox.hidden = false;
}

function severityLabel(sev) {
  return tUI(`sev.${sev}`) || sev;
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

// Findings enthalten Text aus dem gescannten Shop (Review-Ausschnitte, URLs,
// Produkttitel) und aus unseren eigenen Meldungen, in denen Tag-Namen wie
// <title> vorkommen. Beides landet per innerHTML im DOM: ohne Escaping
// oeffnet ein solcher String ein echtes Element - <title> und <iframe>
// verschlucken dabei den gesamten Rest des Reports - und ein praeparierter
// Shop koennte eigenes Markup einschleusen.
function esc(value) {
  return String(value == null ? "" : value).replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
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
          <span class="finding-body"><strong>${esc(f.title)}</strong>${esc(f.detail)}</span>
        </li>`
        )
        .join("");
      return `
      <div class="category-card">
        <div class="category-card-header">
          <div class="category-title"><span class="dot ${color}"></span> ${esc(cat.label)}</div>
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
          <span class="finding-body"><strong>${esc(f.title)}</strong><span class="finding-category">${esc(f.categoryLabel)}</span>${esc(f.detail)}</span>
        </li>`
        )
        .join("")
    : `<li class="finding"><span class="sev-badge sev-info">${tUI("sev.info")}</span><span class="finding-body"><strong>${tUI("report.no_issues_title")}</strong>${tUI("report.no_issues_desc")}</span></li>`;

  const checklistHtml = allIssues.length
    ? allIssues
        .map(
          (f) => `
        <li class="checklist-item">
          <span class="checklist-box"></span>
          <span class="checklist-text">${esc(f.title)} <span class="checklist-cat">– ${esc(f.categoryLabel)}</span></span>
        </li>`
        )
        .join("")
    : `<li class="checklist-item"><span class="checklist-box checked"></span><span class="checklist-text">${tUI("report.no_checklist")}</span></li>`;

  reportContent.innerHTML = `
    ${notice}
    <div class="report-header">
      <h2>${tUI("report.title")}</h2>
      <div class="url">${esc(result.url)}</div>
      <div class="report-ring">
        <svg viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="52" class="ring-bg" />
          <circle cx="60" cy="60" r="52" class="ring-fg ${reportRingColor}" style="stroke-dashoffset:${reportRingOffset}" />
        </svg>
        <div class="report-ring-num">${result.overall_score}</div>
      </div>
      <div class="overall-score">
        <div class="risk ${riskClass(result.overall_score)}">${esc(result.risk_label)}</div>
      </div>
    </div>
    <div class="category-grid">${categoriesHtml}</div>
    <div class="issue-summary">
      <h2>${tUI("report.issues_heading")} (${allIssues.length})</h2>
      <p class="issue-summary-sub">${tUI("report.issues_sub")}</p>
      <ul class="findings-list issue-summary-list">${issuesHtml}</ul>
    </div>
    <div class="issue-checklist">
      <h2>${tUI("report.checklist_heading")}</h2>
      <p class="issue-summary-sub">${tUI("report.checklist_sub")}</p>
      <ul class="checklist">${checklistHtml}</ul>
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
      throw new Error(data.detail || tUI("err.payment_unverified"));
    }
    const result = await resp.json();
    await waitForMinDuration(started);
    renderReport(result);
  } catch (e) {
    showReportError(e.message || tUI("err.unknown_report"));
  }
}

// Blendet Ladeanzeige und Report-Bereich aus. Wird gebraucht, sobald ein
// angestossener Scan doch nicht zu einem Report fuehrt - sonst laeuft der
// Fortschrittsbalken neben der Fehlermeldung einfach weiter.
function resetReportView() {
  stopLoadingAnimation();
  reportSection.hidden = true;
  reportLoading.hidden = true;
}

function showPackageNotice(storeUrl) {
  resetReportView();
  packageNotice.textContent = tUI("package.notice");
  packageNotice.hidden = false;
  document.getElementById("pricing")?.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function buyPackage(url, pkg, triggerBtn) {
  const originalText = triggerBtn.textContent;
  triggerBtn.disabled = true;
  triggerBtn.textContent = tUI("btn.checking");
  try {
    const resp = await fetch("/api/buy-package", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, package: pkg, lang: getLang() }),
    });
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.detail || tUI("err.package_checkout"));
    }
    const data = await resp.json();
    window.location.href = data.checkout_url;
  } catch (e) {
    showError(e.message || tUI("err.package_checkout"));
    triggerBtn.disabled = false;
    triggerBtn.textContent = originalText;
  }
}

const packageModal = document.getElementById("package-modal");
const modalStoreUrl = document.getElementById("modal-store-url");
const modalError = document.getElementById("modal-error");
const modalConfirm = document.getElementById("modal-confirm");
const modalCancel = document.getElementById("modal-cancel");
let pendingPackageBtn = null;

function openPackageModal(pkgBtn) {
  pendingPackageBtn = pkgBtn;
  modalError.hidden = true;
  modalStoreUrl.value = "";
  packageModal.hidden = false;
  modalStoreUrl.focus();
}

function closePackageModal() {
  packageModal.hidden = true;
  pendingPackageBtn = null;
}

modalCancel.addEventListener("click", closePackageModal);
packageModal.addEventListener("click", (e) => {
  if (e.target === packageModal) closePackageModal();
});

modalConfirm.addEventListener("click", async () => {
  const url = modalStoreUrl.value.trim();
  if (!url) {
    modalError.textContent = tUI("err.empty_url");
    modalError.hidden = false;
    return;
  }
  const pkgBtn = pendingPackageBtn;
  const pkg = pkgBtn.getAttribute("data-package");
  closePackageModal();
  await buyPackage(url, pkg, pkgBtn);
});

// Der Rahmen wandert auf das zuletzt angeklickte Paket. Wichtig fuer den
// Fall, dass danach der Domain-Dialog aufgeht: dort muss erkennbar bleiben,
// welches Paket gerade gekauft wird.
function selectPackageCard(pkgBtn) {
  const card = pkgBtn.closest(".pricing-card");
  if (!card) return;
  document
    .querySelectorAll(".pricing-card.is-selected")
    .forEach((el) => el.classList.remove("is-selected"));
  card.classList.add("is-selected");
}

document.querySelectorAll("[data-package]").forEach((pkgBtn) => {
  pkgBtn.addEventListener("click", () => {
    selectPackageCard(pkgBtn);
    const url = document.getElementById("store-url").value.trim();
    if (url) {
      buyPackage(url, pkgBtn.getAttribute("data-package"), pkgBtn);
    } else {
      openPackageModal(pkgBtn);
    }
  });
});

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  errBox.hidden = true;
  packageNotice.hidden = true;

  const url = document.getElementById("store-url").value.trim();

  if (!url) {
    showError(tUI("err.empty_url"));
    return;
  }

  const originalBtnText = btn.textContent;
  btn.disabled = true;
  btn.textContent = tUI("btn.checking");
  const scanStarted = Date.now();
  showLoading();

  try {
    const resp = await fetch("/api/start-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, lang: getLang() }),
    });

    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.detail || tUI("err.start_scan"));
    }

    const data = await resp.json();

    if (data.mode === "redirect") {
      window.location.href = data.checkout_url;
      return;
    }

    if (data.mode === "choose_package") {
      showPackageNotice(url);
      return;
    }

    if (data.mode === "direct") {
      await waitForMinDuration(scanStarted);
      renderReport(data.result);
    }
  } catch (e) {
    resetReportView();
    showError(e.message || tUI("err.unknown"));
  } finally {
    btn.disabled = false;
    btn.textContent = originalBtnText;
  }
});

// Falls wir von Stripe zurückkommen (?session_id=...), Report laden.
if (window.__PENDING_SESSION_ID__) {
  pollScanResult(window.__PENDING_SESSION_ID__);
}
