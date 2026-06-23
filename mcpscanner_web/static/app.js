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

const SEVERITY_ORDER = { HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1, SAFE: 0, UNKNOWN: 0 };
const SEVERITIES = ["HIGH", "MEDIUM", "LOW", "SAFE"];

let _noiseRegexes = null;
function noiseRegexes() {
  if (_noiseRegexes) return _noiseRegexes;
  _noiseRegexes = (state.config.noise_patterns || []).map(globToRegex);
  return _noiseRegexes;
}
function globToRegex(pattern) {
  let out = "^", i = 0;
  while (i < pattern.length) {
    if (pattern.startsWith("**/", i)) { out += "(?:.*/)?"; i += 3; }
    else if (pattern.startsWith("**", i)) { out += ".*"; i += 2; }
    else if (pattern[i] === "*") { out += "[^/]*"; i += 1; }
    else if (pattern[i] === "?") { out += "[^/]"; i += 1; }
    else { out += pattern[i].replace(/[.+^${}()|[\]\\]/g, "\\$&"); i += 1; }
  }
  return new RegExp(out + "$", "i");
}
function isNoise(path) {
  const p = (path || "").replace(/\\/g, "/").replace(/^\.\//, "");
  return noiseRegexes().some((rx) => rx.test(p));
}

function itemSeverity(item) {
  let worst = "SAFE";
  for (const f of item.findings || []) {
    const s = (f.severity || "UNKNOWN").toUpperCase();
    if ((SEVERITY_ORDER[s] || 0) > SEVERITY_ORDER[worst]) worst = s;
  }
  return worst;
}
function itemCategories(item) {
  return [...new Set((item.findings || []).map((f) => f.threat_category).filter(Boolean))];
}
function itemAnalyzers(item) {
  return [...new Set((item.findings || []).map((f) => f.analyzer).filter(Boolean))];
}

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

function renderResults() {
  const panel = $("#results-panel");
  panel.hidden = false;
  panel.innerHTML = "";

  if (!state.outcome.ok) {
    panel.appendChild(el("p", {}, "Scan failed: " + state.outcome.error));
    return;
  }

  const items = state.outcome.items || [];
  panel.appendChild(renderSummary(items));
  panel.appendChild(renderControls(items));

  // partition by noise
  const noisy = items.filter((i) => isNoise(i.name));
  const visiblePool = state.hideNoise ? items.filter((i) => !isNoise(i.name)) : items;

  if (state.hideNoise && noisy.length) {
    const note = el("div", { class: "hidden-note muted" }, [
      `${noisy.length} low-signal items hidden — `,
      el("button", { type: "button", onclick: () => { state.hideNoise = false; renderResults(); } }, "show"),
    ]);
    panel.appendChild(note);
  }

  const rows = applyFiltersSearchSort(visiblePool);
  panel.appendChild(renderTable(rows));
  if (state.selectedItem) panel.appendChild(renderDetail(state.selectedItem));
}

function renderSummary(items) {
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0, SAFE: 0 };
  let unsafe = 0;
  for (const it of items) {
    if (!it.is_safe) unsafe++;
    const sev = itemSeverity(it);
    counts[sev] = (counts[sev] || 0) + 1;
  }
  const wrap = el("div", { class: "summary" });
  wrap.appendChild(el("strong", {}, `${unsafe} unsafe of ${items.length} scanned`));
  for (const s of SEVERITIES) {
    wrap.appendChild(el("span", { class: `sev-badge sev-${s}` }, [
      el("span", { class: `dot ${s}` }), `${s}: ${counts[s] || 0}`,
    ]));
  }
  return wrap;
}

function renderControls(items) {
  const wrap = el("div", { class: "controls" });

  // severity chips
  const sevGroup = el("div", { class: "chip-group" });
  for (const s of SEVERITIES) {
    const active = state.filters.severities.has(s);
    sevGroup.appendChild(el("span", {
      class: "chip" + (active ? " active" : ""),
      onclick: () => { toggleSet(state.filters.severities, s); renderResults(); },
    }, s));
  }
  wrap.appendChild(labeled("Severity", sevGroup));

  // category filter (multi-select)
  const cats = [...new Set(items.flatMap(itemCategories))].sort();
  wrap.appendChild(labeled("Category", multiSelect(cats, state.filters.categories)));

  // analyzer filter
  const ans = [...new Set(items.flatMap(itemAnalyzers))].sort();
  wrap.appendChild(labeled("Analyzer", multiSelect(ans, state.filters.analyzers)));

  // group-by
  const grp = el("select", { onchange: (e) => { state.groupBy = e.target.value; renderResults(); } });
  for (const g of [["item", "Item"], ["severity", "Severity"], ["category", "Category"]]) {
    const opt = el("option", { value: g[0] }, g[1]);
    if (state.groupBy === g[0]) opt.selected = true;
    grp.appendChild(opt);
  }
  wrap.appendChild(labeled("Group by", grp));

  // search
  const search = el("input", {
    type: "search", value: state.search, placeholder: "name / path / summary",
    oninput: (e) => { state.search = e.target.value; renderResults(); },
  });
  wrap.appendChild(labeled("Search", search));

  // noise toggle
  const noiseBtn = el("button", {
    type: "button",
    onclick: () => { state.hideNoise = !state.hideNoise; renderResults(); },
  }, state.hideNoise ? "Show noise" : "Hide likely noise");
  wrap.appendChild(noiseBtn);

  return wrap;
}

function labeled(text, control) {
  return el("div", { class: "control" }, [el("span", { class: "muted" }, text + " "), control]);
}
function toggleSet(set, val) { set.has(val) ? set.delete(val) : set.add(val); }
function multiSelect(options, set) {
  const grp = el("div", { class: "chip-group" });
  for (const o of options) {
    const active = set.has(o);
    grp.appendChild(el("span", {
      class: "chip" + (active ? " active" : ""),
      onclick: () => { toggleSet(set, o); renderResults(); },
    }, o));
  }
  if (!options.length) grp.appendChild(el("span", { class: "muted" }, "—"));
  return grp;
}

function applyFiltersSearchSort(items) {
  let rows = items.slice();
  const f = state.filters;
  if (f.severities.size) rows = rows.filter((i) => f.severities.has(itemSeverity(i)));
  if (f.categories.size) rows = rows.filter((i) => itemCategories(i).some((c) => f.categories.has(c)));
  if (f.analyzers.size) rows = rows.filter((i) => itemAnalyzers(i).some((a) => f.analyzers.has(a)));
  if (state.search.trim()) {
    const q = state.search.toLowerCase();
    rows = rows.filter((i) =>
      (i.name || "").toLowerCase().includes(q) ||
      (i.findings || []).some((fd) => (fd.summary || "").toLowerCase().includes(q))
    );
  }
  const { key, dir } = state.sort;
  const mul = dir === "asc" ? 1 : -1;
  rows.sort((a, b) => mul * compareBy(a, b, key));
  return rows;
}
function compareBy(a, b, key) {
  if (key === "name") return (a.name || "").localeCompare(b.name || "");
  if (key === "status") return (a.is_safe === b.is_safe) ? 0 : (a.is_safe ? -1 : 1);
  return SEVERITY_ORDER[itemSeverity(a)] - SEVERITY_ORDER[itemSeverity(b)];
}

function renderTable(rows) {
  const table = el("table");
  const head = el("tr", {}, [
    sortableTh("Name", "name"),
    sortableTh("Status", "status"),
    sortableTh("Severity", "severity"),
  ]);
  table.appendChild(el("thead", {}, head));
  const body = el("tbody");

  if (state.groupBy === "item") {
    for (const it of rows) body.appendChild(itemRow(it));
  } else {
    const groups = groupRows(rows);
    for (const [label, groupItems] of groups) {
      body.appendChild(el("tr", { class: "group-header" }, el("td", { colspan: "3" }, `${label} (${groupItems.length})`)));
      for (const it of groupItems) body.appendChild(itemRow(it));
    }
  }
  table.appendChild(body);
  return table;
}

function sortableTh(label, key) {
  const arrow = state.sort.key === key ? (state.sort.dir === "asc" ? " ▲" : " ▼") : "";
  return el("th", {
    onclick: () => {
      if (state.sort.key === key) state.sort.dir = state.sort.dir === "asc" ? "desc" : "asc";
      else state.sort = { key, dir: key === "name" ? "asc" : "desc" };
      renderResults();
    },
  }, label + arrow);
}

function groupRows(rows) {
  const map = new Map();
  for (const it of rows) {
    const keys = state.groupBy === "severity" ? [itemSeverity(it)]
      : (itemCategories(it).length ? itemCategories(it) : ["(none)"]);
    for (const k of keys) {
      if (!map.has(k)) map.set(k, []);
      map.get(k).push(it);
    }
  }
  return [...map.entries()].sort((a, b) => {
    if (state.groupBy === "severity") return SEVERITY_ORDER[b[0]] - SEVERITY_ORDER[a[0]];
    return a[0].localeCompare(b[0]);
  });
}

function itemRow(it) {
  const sev = itemSeverity(it);
  const selected = state.selectedItem === it ? " selected" : "";
  return el("tr", {
    class: "row-item" + selected,
    onclick: () => { state.selectedItem = it; renderResults(); },
  }, [
    el("td", {}, it.name),
    el("td", {}, it.is_safe ? "safe" : "unsafe"),
    el("td", {}, el("span", { class: "sev-label " + sev }, [el("span", { class: "dot " + sev }), " " + sev])),
  ]);
}

// renderDetail is added in Task 13.
function renderDetail() { return el("div"); }

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
