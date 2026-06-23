// mcpscanner_web/static/app.js
const $ = (sel) => document.querySelector(sel);

const state = {
  config: null,
  outcome: null,
  selectedItem: null,
  filters: { severities: new Set(), categories: new Set(), analyzers: new Set() },
  groupBy: "item",
  sort: { key: "severity", dir: "desc" },
  search: "",
  hideNoise: true,
};

async function api(path, opts) {
  const r = await fetch(path, opts);
  return r.json();
}

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "hidden") node.hidden = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) node.setAttribute(k, v);
  }
  for (const c of [].concat(children)) {
    if (c == null) continue;
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

function renderScanForm() {
  const cfg = state.config;
  $("#version").textContent = "v" + cfg.version;

  const typeSel = $("#scan-type");
  typeSel.innerHTML = "";
  for (const t of cfg.scan_types) {
    typeSel.appendChild(el("option", { value: t }, labelForType(t)));
  }
  typeSel.value = state.scanType || cfg.scan_types[0];
  state.scanType = typeSel.value;
  typeSel.onchange = () => { state.scanType = typeSel.value; rebuildForType(); };

  const provSel = $("#llm-provider");
  provSel.innerHTML = "";
  for (const p of cfg.llm_providers) {
    provSel.appendChild(el("option", { value: p.id }, p.label));
  }
  provSel.value = cfg.default_llm_provider;
  provSel.onchange = () => {
    const p = cfg.llm_providers.find((x) => x.id === provSel.value);
    $("#llm-model").value = p ? p.default_model : "";
  };

  $("#scan-btn").onclick = runScan;
  $("#settings-btn").onclick = openSettings;
  rebuildForType();
}

function labelForType(t) {
  return { remote: "Remote server URL", stdio: "Stdio server", files: "Source code / files" }[t] || t;
}

function rebuildForType() {
  const t = state.scanType;
  $("#target-label").firstChild.textContent =
    ({ remote: "URL", stdio: "Command", files: "Path" }[t] || "Target") + " ";
  $("#bearer-row").hidden = t !== "remote";
  $("#timeout-row").hidden = t !== "stdio";

  const fs = $("#analyzers");
  fs.innerHTML = "<legend>Analyzers</legend>";
  for (const a of state.config.analyzers_by_type[t]) {
    const cb = el("input", { type: "checkbox", value: a, onchange: refreshLlmRow });
    fs.appendChild(el("label", { class: "inline" }, [cb, " " + a]));
  }
  refreshLlmRow();
}

function selectedAnalyzers() {
  return [...document.querySelectorAll("#analyzers input:checked")].map((c) => c.value);
}

function refreshLlmRow() {
  const needsLlm = selectedAnalyzers().some((a) => a === "llm" || a === "behavioral");
  $("#llm-row").hidden = !needsLlm;
}

async function runScan() {
  const payload = {
    scan_type: state.scanType,
    target: $("#target").value,
    analyzers: selectedAnalyzers(),
    bearer_token: $("#bearer").value || null,
    llm_provider: $("#llm-provider").value,
    llm_model: $("#llm-model").value || null,
    stdio_timeout: parseInt($("#stdio-timeout").value, 10) || 60,
  };
  $("#scan-status").textContent = "Starting…";
  const res = await api("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (res.error) {
    $("#scan-status").textContent = "Error: " + res.error;
    return;
  }
  streamScan(res.job_id);
}

function streamScan(jobId) {
  const src = new EventSource(`/api/scan/${jobId}/events`);
  $("#scan-status").textContent = "Scanning…";
  src.addEventListener("progress", () => {
    $("#scan-status").textContent = "Scanning…";
  });
  src.addEventListener("result", (e) => {
    state.outcome = JSON.parse(e.data);
    renderResults();
  });
  src.addEventListener("done", () => {
    $("#scan-status").textContent = "Done.";
    src.close();
  });
  src.onerror = () => {
    $("#scan-status").textContent = "Connection lost.";
    src.close();
  };
}

// Stub — replaced in Task 12.
function renderResults() {
  const panel = $("#results-panel");
  panel.hidden = false;
  if (!state.outcome.ok) {
    panel.textContent = "Scan failed: " + state.outcome.error;
    return;
  }
  panel.textContent = `${state.outcome.items.length} items scanned`;
}

async function openSettings() {
  // Expanded in Task 14 / Task 23. Minimal stub for now.
  $("#settings-dialog").showModal();
}

async function boot() {
  state.config = await api("/api/config");
  const prefs = (await api("/api/prefs")).prefs || {};
  if (prefs.llm_provider) state.defaultProvider = prefs.llm_provider;
  renderScanForm();
  if (prefs.llm_model) $("#llm-model").value = prefs.llm_model;
}

boot();
