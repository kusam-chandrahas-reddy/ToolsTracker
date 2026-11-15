/**
 * Veracode Sandbox Vulnerability & Metrics Tracker Frontend Logic
 * Multi-Application & Multi-Sandbox Selection, Metrics Matrix, Reports & Exports.
 */

// Global Application State
const state = {
  systemStatus: null,
  applications: [],
  selectedAppGuids: [],     // Array of selected application GUIDs
  sandboxes: [],            // Sandboxes across selected applications
  selectedSandboxGuids: [], // Array of selected sandbox GUIDs
  sandboxesStatusList: [],  // Status objects for selected sandboxes
  metrics: null,
  findings: [],
  filteredFindings: [],
  scanTypeFilter: "ALL",
  severityFilter: "ALL",
  mitigationFilter: "ALL",
  searchKeyword: "",
  openOnlyFilter: false
};

// ================= INITIALIZATION =================
document.addEventListener("DOMContentLoaded", async () => {
  await fetchSystemStatus();
  await loadApplications();
});

// ================= API CALLS =================

async function fetchSystemStatus() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) throw new Error("Failed to fetch system status");
    state.systemStatus = await res.json();
    updateConnectionBadge(state.systemStatus);
  } catch (err) {
    console.error("fetchSystemStatus error:", err);
  }
}

async function loadApplications(forceRefresh = false) {
  const appList = document.getElementById("multiAppList");
  appList.innerHTML = '<div class="p-4 text-center text-slate-500 text-xs"><i class="fa-solid fa-spinner fa-spin text-blue-400 mb-1 block"></i>Loading applications...</div>';

  try {
    const res = await fetch(`/api/applications?refresh=${forceRefresh}`);
    if (!res.ok) throw new Error("Failed to load applications");
    const data = await res.json();
    state.applications = data.applications || [];

    if (data.warning) {
      console.warn(data.warning);
    }

    // Default: select the first application (or all)
    if (state.applications.length > 0) {
      state.selectedAppGuids = [state.applications[0].guid];
    } else {
      state.selectedAppGuids = [];
    }

    renderMultiAppControl();
    await loadSandboxesForSelectedApps(forceRefresh);
  } catch (err) {
    console.error("loadApplications error:", err);
    appList.innerHTML = '<div class="p-4 text-center text-red-400 text-xs">Error loading applications.</div>';
  }
}

async function loadSandboxesForSelectedApps(forceRefresh = false) {
  if (state.selectedAppGuids.length === 0) {
    state.sandboxes = [];
    state.selectedSandboxGuids = [];
    renderMultiSandboxControl();
    clearViewNoSandboxes();
    return;
  }

  const sbList = document.getElementById("multiSandboxList");
  sbList.innerHTML = '<div class="p-4 text-center text-slate-500 text-xs"><i class="fa-solid fa-spinner fa-spin text-emerald-400 mb-1 block"></i>Loading sandboxes across selected applications...</div>';

  try {
    const appGuidsParam = state.selectedAppGuids.join(",");
    const res = await fetch(`/api/sandboxes?app_guids=${appGuidsParam}&refresh=${forceRefresh}`);
    if (!res.ok) throw new Error("Failed to load sandboxes");
    const data = await res.json();
    state.sandboxes = data.sandboxes || [];

    // Pre-select all available sandboxes across the selected apps
    state.selectedSandboxGuids = state.sandboxes.map(s => s.guid);

    renderMultiSandboxControl();
    await loadSelectedSandboxesData(forceRefresh);
  } catch (err) {
    console.error("loadSandboxesForSelectedApps error:", err);
    sbList.innerHTML = '<div class="p-4 text-center text-red-400 text-xs">Error loading sandboxes.</div>';
  }
}

async function loadSelectedSandboxesData(forceRefresh = false) {
  if (state.selectedAppGuids.length === 0 || state.selectedSandboxGuids.length === 0) {
    clearViewNoSandboxes();
    return;
  }

  setLoadingState(true);
  const appGuidsParam = state.selectedAppGuids.join(",");
  const sbGuidsParam = state.selectedSandboxGuids.join(",");

  try {
    // 1. Fetch statuses for all selected sandboxes
    const statusPromise = fetch(`/api/sandboxes/status?app_guids=${appGuidsParam}&sandbox_guids=${sbGuidsParam}`).then(r => r.json());
    
    // 2. Fetch metrics aggregated across selected applications & sandboxes
    const metricsPromise = fetch(`/api/sandboxes/metrics?app_guids=${appGuidsParam}&sandbox_guids=${sbGuidsParam}`).then(r => r.json());
    
    // 3. Fetch reported instances
    const findingsPromise = fetch(`/api/sandboxes/findings?app_guids=${appGuidsParam}&sandbox_guids=${sbGuidsParam}&scan_type=ALL`).then(r => r.json());

    const [statusData, metricsData, findingsData] = await Promise.all([
      statusPromise,
      metricsPromise,
      findingsPromise
    ]);

    state.sandboxesStatusList = statusData.statuses || [];
    state.metrics = metricsData.metrics || null;
    state.findings = findingsData.findings || [];

    // Render components
    renderScanStatuses(state.sandboxesStatusList);
    renderMetrics(state.metrics);
    applyFilters();

    // Load Veracode native report availability (live mode only)
    await loadVericodeReportInfo();

  } catch (err) {
    console.error("loadSelectedSandboxesData error:", err);
  } finally {
    setLoadingState(false);
  }
}

// ================= MULTI-APPLICATION UI =================

function renderMultiAppControl() {
  const container = document.getElementById("multiAppList");
  const countBadge = document.getElementById("selectedAppsCountBadge");
  const totalHint = document.getElementById("appTotalCountHint");
  container.innerHTML = "";

  const total = state.applications.length;
  const count = state.selectedAppGuids.length;

  if (countBadge) countBadge.textContent = `${count} of ${total} Selected`;
  if (totalHint) totalHint.textContent = `Total: ${total} apps`;

  if (total === 0) {
    container.innerHTML = '<div class="p-4 text-center text-slate-500 text-xs">No applications discovered.</div>';
    return;
  }

  state.applications.forEach(app => {
    const isChecked = state.selectedAppGuids.includes(app.guid);
    const item = document.createElement("label");
    item.className = `flex items-center justify-between p-2.5 rounded-lg border transition cursor-pointer ${
      isChecked 
        ? "bg-slate-800/90 border-blue-500/60 shadow-sm" 
        : "bg-slate-950/60 border-slate-800/80 hover:bg-slate-800/40 text-slate-400"
    }`;

    let critBadgeCls = "bg-slate-800 text-slate-300 border-slate-700";
    const crit = (app.business_criticality || "").toUpperCase();
    if (crit.includes("VERY HIGH")) critBadgeCls = "bg-red-950 text-red-300 border-red-800";
    else if (crit.includes("HIGH")) critBadgeCls = "bg-orange-950 text-orange-300 border-orange-800";
    else if (crit.includes("MEDIUM")) critBadgeCls = "bg-amber-950 text-amber-300 border-amber-800";

    item.innerHTML = `
      <div class="flex items-center space-x-2.5 min-w-0 pr-2">
        <input type="checkbox" value="${escapeHtml(app.guid)}" ${isChecked ? 'checked' : ''} onchange="onAppCheckboxChange(this)" class="w-4 h-4 rounded bg-slate-950 border-slate-600 text-blue-500 focus:ring-0 cursor-pointer">
        <div class="truncate">
          <div class="font-bold text-xs ${isChecked ? 'text-white' : 'text-slate-300'} truncate">${escapeHtml(app.name || 'Application')}</div>
          <div class="text-[10px] text-slate-400 flex items-center space-x-2 mt-0.5">
            <span class="code-font text-slate-500 truncate max-w-[8rem]">${escapeHtml(app.guid.substring(0, 8))}...</span>
            <span>•</span>
            <span class="truncate max-w-[12rem]">${escapeHtml(app.policy_name || 'Standard Policy')}</span>
          </div>
        </div>
      </div>
      <span class="text-[9px] font-bold px-2 py-0.5 rounded-full border ${critBadgeCls} flex-shrink-0 uppercase">
        ${escapeHtml(app.business_criticality || 'Normal')}
      </span>
    `;
    container.appendChild(item);
  });
}

function onAppCheckboxChange(checkbox) {
  const guid = checkbox.value;
  if (checkbox.checked) {
    if (!state.selectedAppGuids.includes(guid)) {
      state.selectedAppGuids.push(guid);
    }
  } else {
    state.selectedAppGuids = state.selectedAppGuids.filter(g => g !== guid);
  }
  renderMultiAppControl();
  loadSandboxesForSelectedApps();
}

function selectAllApplications() {
  state.selectedAppGuids = state.applications.map(a => a.guid);
  renderMultiAppControl();
  loadSandboxesForSelectedApps();
}

function clearApplicationSelection() {
  state.selectedAppGuids = [];
  renderMultiAppControl();
  loadSandboxesForSelectedApps();
}

// ================= MULTI-SANDBOX UI =================

function renderMultiSandboxControl() {
  const container = document.getElementById("multiSandboxList");
  const countBadge = document.getElementById("selectedCountBadge");
  const totalHint = document.getElementById("sandboxTotalCountHint");
  container.innerHTML = "";

  const total = state.sandboxes.length;
  const count = state.selectedSandboxGuids.length;

  if (countBadge) countBadge.textContent = `${count} of ${total} Selected`;
  if (totalHint) totalHint.textContent = `Total: ${total} sandboxes`;

  if (state.selectedAppGuids.length === 0) {
    container.innerHTML = '<div class="p-4 text-center text-slate-500 text-xs">Select at least one application to view sandboxes.</div>';
    return;
  }

  if (total === 0) {
    container.innerHTML = '<div class="p-4 text-center text-slate-500 text-xs"><i class="fa-solid fa-box-open text-lg mb-1 block text-slate-600"></i>No development sandboxes found for the selected application(s).</div>';
    return;
  }

  state.sandboxes.forEach(sb => {
    const isChecked = state.selectedSandboxGuids.includes(sb.guid);
    const item = document.createElement("label");
    item.className = `flex items-center justify-between p-2.5 rounded-lg border transition cursor-pointer ${
      isChecked 
        ? "bg-slate-800/90 border-emerald-500/50 shadow-sm" 
        : "bg-slate-950/60 border-slate-800/80 hover:bg-slate-800/40 text-slate-400"
    }`;

    const rawStatus = (sb.status || "READY").toUpperCase();
    let statusPillClass = "bg-emerald-950 text-emerald-300 border-emerald-800";
    if (rawStatus.includes("SCANNING") || rawStatus.includes("PROGRESS")) {
      statusPillClass = "bg-amber-950 text-amber-300 border-amber-800";
    }

    const modifiedDate = formatDate(sb.modified || sb.created);
    const appLabel = sb.application_name ? `<span class="bg-slate-800 text-cyan-400 border border-slate-700 px-1 rounded text-[9px] truncate max-w-[8rem]">${escapeHtml(sb.application_name)}</span>` : '';

    item.innerHTML = `
      <div class="flex items-center space-x-2.5 min-w-0 pr-2">
        <input type="checkbox" value="${escapeHtml(sb.guid)}" ${isChecked ? 'checked' : ''} onchange="onSandboxCheckboxChange(this)" class="w-4 h-4 rounded bg-slate-950 border-slate-600 text-emerald-500 focus:ring-0 cursor-pointer">
        <div class="truncate">
          <div class="flex items-center space-x-1.5 truncate">
            ${appLabel}
            <span class="font-bold text-xs ${isChecked ? 'text-white' : 'text-slate-300'} truncate">${escapeHtml(sb.name || 'Sandbox')}</span>
          </div>
          <div class="text-[10px] text-slate-400 flex items-center space-x-2 mt-0.5">
            <span class="truncate max-w-[9rem]">${escapeHtml(sb.owner || 'Enterprise User')}</span>
            <span>•</span>
            <span>${modifiedDate}</span>
          </div>
        </div>
      </div>
      <span class="text-[9px] font-bold px-2 py-0.5 rounded-full border ${statusPillClass} flex-shrink-0 uppercase">
        ${escapeHtml(sb.status || 'READY')}
      </span>
    `;
    container.appendChild(item);
  });
}

function onSandboxCheckboxChange(checkbox) {
  const guid = checkbox.value;
  if (checkbox.checked) {
    if (!state.selectedSandboxGuids.includes(guid)) {
      state.selectedSandboxGuids.push(guid);
    }
  } else {
    state.selectedSandboxGuids = state.selectedSandboxGuids.filter(g => g !== guid);
  }
  renderMultiSandboxControl();
  loadSelectedSandboxesData();
}

function selectAllSandboxes() {
  state.selectedSandboxGuids = state.sandboxes.map(s => s.guid);
  renderMultiSandboxControl();
  loadSelectedSandboxesData();
}

function clearSandboxSelection() {
  state.selectedSandboxGuids = [];
  renderMultiSandboxControl();
  clearViewNoSandboxes();
}

// ================= RENDER LOGIC =================

function updateConnectionBadge(status) {
  const badgeDot = document.getElementById("statusIndicatorDot");
  const badgeText = document.getElementById("statusBadgeText");
  const regionBadge = document.getElementById("regionBadge");
  const noticeBox = document.getElementById("activeModeNotice");

  if (!status) return;

  regionBadge.textContent = (status.region || "us").toUpperCase();

  if (status.mock_mode || !status.has_credentials) {
    badgeDot.className = "w-2.5 h-2.5 rounded-full bg-cyan-400 status-pulse-cyan";
    badgeText.textContent = "Simulation Mode (Offline Demo)";
    if (noticeBox) {
      noticeBox.textContent = "DEMO SIMULATION ACTIVE";
      noticeBox.className = "hidden sm:inline-block font-mono text-[11px] text-cyan-400 bg-cyan-950/60 border border-cyan-800/50 px-2.5 py-1 rounded";
    }
  } else {
    badgeDot.className = "w-2.5 h-2.5 rounded-full bg-emerald-400 status-pulse-green";
    badgeText.textContent = `Live Veracode API (${status.masked_api_id || "Active"})`;
    if (noticeBox) {
      noticeBox.textContent = "LIVE VERACODE API CONNECTED";
      noticeBox.className = "hidden sm:inline-block font-mono text-[11px] text-emerald-400 bg-emerald-950/60 border border-emerald-800/50 px-2.5 py-1 rounded";
    }
  }
}

function renderScanStatuses(statuses) {
  const container = document.getElementById("sandboxesStatusContainer");
  const countEl = document.getElementById("statusReportedCount");
  container.innerHTML = "";

  countEl.textContent = statuses.length;

  if (statuses.length === 0) {
    container.innerHTML = '<div class="col-span-full p-4 text-center text-slate-500">No sandbox scan statuses to display. Select one or more sandboxes above.</div>';
    return;
  }

  statuses.forEach(sb => {
    const card = document.createElement("div");
    card.className = "bg-slate-900 border border-slate-800 p-3.5 rounded-xl shadow-sm space-y-2";

    const rawStatus = (sb.scan_status || "Results Ready").toUpperCase();
    let statusPillClass = "bg-emerald-900/80 text-emerald-200 border-emerald-600";
    let iconClass = "fa-clipboard-check text-emerald-400";

    if (rawStatus.includes("SCANNING") || rawStatus.includes("PROGRESS") || sb.is_scan_in_progress) {
      statusPillClass = "bg-amber-900/80 text-amber-200 border-amber-600 animate-pulse";
      iconClass = "fa-spinner fa-spin text-amber-400";
    } else if (rawStatus.includes("PRESCAN") || rawStatus.includes("SUBMITTED")) {
      statusPillClass = "bg-blue-900/80 text-blue-200 border-blue-600";
      iconClass = "fa-cloud-arrow-up text-blue-400";
    }

    const appPrefix = sb.application_name ? `<span class="text-cyan-400 font-mono text-[10px] mr-1">[${escapeHtml(sb.application_name)}]</span>` : '';

    card.innerHTML = `
      <div class="flex items-center justify-between">
        <div class="font-bold text-slate-200 text-xs truncate max-w-[14rem]" title="${escapeHtml(sb.sandbox_name || 'Sandbox')}">
          ${appPrefix}
          <i class="fa-solid fa-box-archive text-emerald-400 mr-1"></i>${escapeHtml(sb.sandbox_name || 'Sandbox')}
        </div>
        <span class="text-[10px] font-bold px-2 py-0.5 rounded-full border ${statusPillClass}">
          <i class="fa-solid ${iconClass} mr-1"></i>${escapeHtml(sb.scan_status || 'Results Ready')}
        </span>
      </div>
      <div class="grid grid-cols-3 gap-2 text-[10px] text-slate-400 pt-1 border-t border-slate-800/80">
        <div>
          <span class="text-slate-500 block uppercase text-[9px]">Build ID</span>
          <span class="font-mono text-cyan-400 font-semibold">${escapeHtml(sb.build_id ? '#' + sb.build_id : 'N/A')}</span>
        </div>
        <div>
          <span class="text-slate-500 block uppercase text-[9px]">Version</span>
          <span class="font-mono text-slate-300 truncate block" title="${escapeHtml(sb.version || 'latest')}">${escapeHtml(sb.version || 'latest')}</span>
        </div>
        <div>
          <span class="text-slate-500 block uppercase text-[9px]">Scan Date</span>
          <span class="text-slate-300">${formatDate(sb.last_scan_date)}</span>
        </div>
      </div>
    `;
    container.appendChild(card);
  });
}

function renderMetrics(metrics) {
  if (!metrics) return;

  const kpis = metrics.kpis || {};
  document.getElementById("kpiTotalFlaws").textContent = kpis.total_flaws || 0;
  document.getElementById("kpiCritHigh").textContent = kpis.critical_high || 0;
  document.getElementById("kpiUnmitigated").textContent = kpis.unmitigated_count || 0;
  document.getElementById("kpiMitProposed").textContent = kpis.mit_proposed_count || 0;
  document.getElementById("kpiMitApproved").textContent = kpis.mit_approved_count || 0;
  document.getElementById("kpiSastCount").textContent = kpis.sast_count || 0;
  document.getElementById("kpiScaCount").textContent = kpis.sca_count || 0;
  document.getElementById("kpiFixed").textContent = kpis.fixed_count || 0;

  // Render Table 1: Scan Type x Severity x Mitigation Status Data
  renderSeverityMitigationMatrixTable(metrics.severity_mitigation_matrix || []);

  // Render Table 2: Mitigation Summary
  renderMitigationSummaryTable(metrics.mitigation_table || []);

  // Render Table 3: Per-Sandbox Summary
  renderSandboxesSummaryTable(metrics.sandboxes_table || []);

  // Render Table 4: SAST CWE
  renderSastCweTable(metrics.sast_cwe_table || []);

  // Render Table 5: SCA Components
  renderScaComponentsTable(metrics.sca_components_table || []);
}

function renderSeverityMitigationMatrixTable(rows) {
  const tbody = document.getElementById("severityMitigationMatrixTableBody");
  tbody.innerHTML = "";

  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="px-4 py-4 text-center text-slate-500">No matrix metrics available</td></tr>';
    return;
  }

  rows.forEach(r => {
    const isSub = r.is_subtotal;
    const isGrand = r.is_grand_total;
    const tr = document.createElement("tr");

    if (isGrand) {
      tr.className = "bg-slate-800 font-bold border-t-2 border-cyan-500 text-white";
    } else if (isSub) {
      tr.className = "bg-slate-800/80 font-bold border-t border-slate-700 text-slate-200";
    } else {
      tr.className = "table-row-hover text-slate-300";
    }

    const sevPill = r.severity_num >= 0 
      ? getSeverityBadgeHtml(r.severity_num, r.severity_label)
      : `<span class="font-bold text-slate-300">${r.severity_label}</span>`;

    tr.innerHTML = `
      <td class="px-4 py-2.5 font-medium ${isGrand ? 'text-cyan-400 font-bold' : ''}">
        ${escapeHtml(r.scan_type)}
      </td>
      <td class="px-3 py-2.5 text-center">${sevPill}</td>
      <td class="px-3 py-2.5 text-center font-bold text-white bg-slate-800/50">${r.total || 0}</td>
      <td class="px-3 py-2.5 text-center text-rose-400 font-bold">${r.unmitigated || 0}</td>
      <td class="px-3 py-2.5 text-center text-blue-400 font-semibold">${r.mitigation_proposed || 0}</td>
      <td class="px-3 py-2.5 text-center text-cyan-400 font-semibold">${r.mitigation_approved || 0}</td>
      <td class="px-3 py-2.5 text-center text-purple-400">${r.mitigation_rejected || 0}</td>
      <td class="px-3 py-2.5 text-center text-emerald-400 font-bold">${r.fixed_resolved || 0}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderMitigationSummaryTable(rows) {
  const tbody = document.getElementById("mitigationSummaryTableBody");
  tbody.innerHTML = "";

  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="px-3 py-4 text-center text-slate-500">No mitigation data available</td></tr>';
    return;
  }

  rows.forEach(r => {
    const tr = document.createElement("tr");
    tr.className = "table-row-hover";
    const badge = getMitigationBadgeHtml(r.mitigation_status);

    tr.innerHTML = `
      <td class="px-3 py-2.5 font-medium">${badge}</td>
      <td class="px-3 py-2.5 text-center text-blue-400 font-mono font-bold">${r.sast || 0}</td>
      <td class="px-3 py-2.5 text-center text-purple-400 font-mono font-bold">${r.sca || 0}</td>
      <td class="px-3 py-2.5 text-center font-bold text-white">${r.total || 0}</td>
      <td class="px-3 py-2.5 text-right font-mono text-slate-300">${r.percentage}%</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderSandboxesSummaryTable(rows) {
  const tbody = document.getElementById("sandboxesSummaryTableBody");
  tbody.innerHTML = "";

  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="px-3 py-4 text-center text-slate-500">No sandboxes selected</td></tr>';
    return;
  }

  rows.forEach(r => {
    const tr = document.createElement("tr");
    tr.className = "table-row-hover";

    tr.innerHTML = `
      <td class="px-3 py-2.5 font-medium text-slate-200 truncate max-w-[12rem]" title="${escapeHtml(r.name)}">
        <i class="fa-solid fa-box-archive text-emerald-400 mr-1.5 text-xs"></i>${escapeHtml(r.name)}
      </td>
      <td class="px-3 py-2.5 text-center font-mono text-[10px] text-slate-400">${escapeHtml(r.scan_status || 'Ready')}</td>
      <td class="px-3 py-2.5 text-center font-bold text-white">${r.total || 0}</td>
      <td class="px-3 py-2.5 text-center text-red-400 font-bold">${r.crit_high || 0}</td>
      <td class="px-3 py-2.5 text-center text-rose-400 font-bold">${r.unmitigated || 0}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderSastCweTable(cwes) {
  const tbody = document.getElementById("sastCweTableBody");
  tbody.innerHTML = "";

  if (cwes.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="px-3 py-4 text-center text-slate-500">No SAST flaws recorded in selected sandboxes.</td></tr>';
    return;
  }

  cwes.forEach(c => {
    const tr = document.createElement("tr");
    tr.className = "table-row-hover";
    const sevBadge = getSeverityBadgeHtml(c.max_severity, c.max_severity_label);

    tr.innerHTML = `
      <td class="px-3 py-2.5 text-center text-slate-500 font-mono text-[11px]">${c.rank}</td>
      <td class="px-3 py-2.5 font-mono text-cyan-400 font-medium">${c.cwe_id}</td>
      <td class="px-3 py-2.5 text-slate-200 truncate max-w-xs" title="${escapeHtml(c.cwe_name)}">${escapeHtml(c.category || c.cwe_name)}</td>
      <td class="px-3 py-2.5 text-center font-bold text-white">${c.count}</td>
      <td class="px-3 py-2.5 text-center text-rose-400 font-bold">${c.unmitigated || 0}</td>
      <td class="px-3 py-2.5 text-center">${sevBadge}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderScaComponentsTable(comps) {
  const tbody = document.getElementById("scaComponentsTableBody");
  tbody.innerHTML = "";

  if (comps.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="px-3 py-4 text-center text-slate-500">No vulnerable SCA components reported.</td></tr>';
    return;
  }

  comps.forEach(c => {
    const tr = document.createElement("tr");
    tr.className = "table-row-hover";
    const cvssColor = c.max_cvss >= 9.0 ? "text-red-400 font-bold" : (c.max_cvss >= 7.0 ? "text-orange-400 font-bold" : "text-amber-400");
    const cveString = Array.isArray(c.cves) ? c.cves.join(", ") : (c.cves || "N/A");

    tr.innerHTML = `
      <td class="px-3 py-2.5 font-mono text-slate-200 truncate max-w-xs" title="${escapeHtml(c.component)}">${escapeHtml(c.component)}</td>
      <td class="px-3 py-2.5 font-mono text-slate-400">${escapeHtml(c.version)}</td>
      <td class="px-3 py-2.5 font-mono text-cyan-300 truncate max-w-[10rem]" title="${escapeHtml(cveString)}">${escapeHtml(cveString)}</td>
      <td class="px-3 py-2.5 text-center font-mono ${cvssColor}">${c.max_cvss ? c.max_cvss.toFixed(1) : 'N/A'}</td>
      <td class="px-3 py-2.5 text-center font-bold text-white">${c.flaw_count}</td>
      <td class="px-3 py-2.5 text-center text-rose-400 font-bold">${c.unmitigated || 0}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderVulnerabilitiesTable(findings) {
  const tbody = document.getElementById("vulnerabilitiesTableBody");
  const countDisplay = document.getElementById("vulnerabilityCountDisplay");
  tbody.innerHTML = "";

  countDisplay.textContent = `Showing ${findings.length} of ${state.findings.length} reported instances across selected applications & sandboxes`;

  if (findings.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="12" class="px-4 py-8 text-center text-slate-500">
          <i class="fa-solid fa-check-circle text-2xl text-emerald-500/60 mb-2"></i>
          <div>No vulnerabilities match the selected filters or no sandboxes/applications are selected.</div>
        </td>
      </tr>
    `;
    return;
  }

  findings.forEach(f => {
    const tr = document.createElement("tr");
    tr.className = "table-row-hover cursor-pointer";
    tr.onclick = () => openDetailModal(f);

    const typeBadge = f.scan_type === "SAST" 
      ? '<span class="text-[10px] font-bold px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800">SAST</span>'
      : '<span class="text-[10px] font-bold px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">SCA</span>';

    const sevBadge = getSeverityBadgeHtml(f.severity, f.severity_label);
    const mitBadge = getMitigationBadgeHtml(f.mitigation_status);

    const title = f.scan_type === "SAST" 
      ? (f.category || f.cwe_name || "Static Flaw")
      : (f.cve_id ? `${f.cve_id} in ${f.component_filename || 'Component'}` : (f.category || "Vulnerable Component"));

    const location = f.scan_type === "SAST"
      ? (f.file_name ? `${f.file_name}:${f.line_number || '?'}` : (f.file_path || "N/A"))
      : (f.component_filename ? `${f.component_filename} (${f.version || 'unknown'})` : (f.file_name || "N/A"));

    const appBadge = `<span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-blue-300 border border-slate-700 truncate max-w-[8rem] inline-block" title="${escapeHtml(f.application_name || 'App')}">${escapeHtml(f.application_name || 'App')}</span>`;
    const sbBadge = `<span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 truncate max-w-[8rem] inline-block" title="${escapeHtml(f.sandbox_name || 'Sandbox')}">${escapeHtml(f.sandbox_name || 'Sandbox')}</span>`;
    const moduleName = f.module || f.component_filename || f.file_name || "N/A";
    const moduleBadge = `<span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900/90 text-amber-300 border border-slate-700 truncate max-w-[7.5rem] inline-block" title="${escapeHtml(moduleName)}">${escapeHtml(moduleName)}</span>`;

    const descText = f.description || "No description provided.";
    const firstFound = formatDate(f.first_found_date);

    tr.innerHTML = `
      <td class="px-2.5 py-2.5">${appBadge}</td>
      <td class="px-2.5 py-2.5">${sbBadge}</td>
      <td class="px-2.5 py-2.5">${moduleBadge}</td>
      <td class="px-2 py-2.5 text-center">${typeBadge}</td>
      <td class="px-2.5 py-2.5 font-mono text-cyan-400 font-semibold">${f.issue_id || 'N/A'}</td>
      <td class="px-2 py-2.5 text-center">${sevBadge}</td>
      <td class="px-3 py-2.5 font-medium text-slate-200 max-w-xs truncate" title="${escapeHtml(title)}">
        ${escapeHtml(title)}
      </td>
      <td class="px-3 py-2.5 text-slate-400 max-w-xs truncate" title="${escapeHtml(descText)}">
        ${escapeHtml(descText)}
      </td>
      <td class="px-2.5 py-2.5 text-center">${mitBadge}</td>
      <td class="px-2.5 py-2.5 text-center text-slate-300 text-[11px] whitespace-nowrap">${firstFound}</td>
      <td class="px-2.5 py-2.5 font-mono text-slate-400 max-w-xs truncate" title="${escapeHtml(location)}">
        ${escapeHtml(location)}
      </td>
      <td class="px-2 py-2.5 text-center">
        <button class="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800 transition" title="Inspect Flaw Details">
          <i class="fa-solid fa-arrow-up-right-from-square"></i>
        </button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function getSeverityBadgeHtml(num, label) {
  let cls = "badge-info";
  if (num === 5) cls = "badge-very-high";
  else if (num === 4) cls = "badge-high";
  else if (num === 3) cls = "badge-medium";
  else if (num === 2) cls = "badge-low";
  else if (num === 1) cls = "badge-very-low";

  return `<span class="px-2 py-0.5 rounded text-[10px] inline-block font-bold ${cls}">${label || 'Info'}</span>`;
}

function getMitigationBadgeHtml(statusStr) {
  const st = statusStr || "Unmitigated";
  let cls = "badge-mit-unmitigated";

  if (st === "Mitigation Proposed") cls = "badge-mit-proposed";
  else if (st === "Mitigation Approved") cls = "badge-mit-approved";
  else if (st === "Mitigation Rejected") cls = "badge-mit-rejected";
  else if (st === "Fixed / Resolved") cls = "badge-mit-fixed";

  return `<span class="px-2 py-0.5 rounded text-[10px] inline-block font-semibold ${cls}">${escapeHtml(st)}</span>`;
}

// ================= FILTERING LOGIC =================

function applyFilters() {
  const searchInput = document.getElementById("filterSearch");
  const sevSelect = document.getElementById("filterSeverity");
  const mitSelect = document.getElementById("filterMitigation");
  const openCheckbox = document.getElementById("filterOpenOnly");

  state.searchKeyword = (searchInput ? searchInput.value : "").trim().toLowerCase();
  state.severityFilter = sevSelect ? sevSelect.value : "ALL";
  state.mitigationFilter = mitSelect ? mitSelect.value : "ALL";
  state.openOnlyFilter = openCheckbox ? openCheckbox.checked : false;

  state.filteredFindings = state.findings.filter(f => {
    // Scan Type Filter
    if (state.scanTypeFilter !== "ALL" && f.scan_type !== state.scanTypeFilter) {
      return false;
    }

    // Severity Filter
    if (state.severityFilter !== "ALL" && String(f.severity) !== state.severityFilter) {
      return false;
    }

    // Mitigation Status Filter
    if (state.mitigationFilter !== "ALL" && f.mitigation_status !== state.mitigationFilter) {
      return false;
    }

    // Open Only Filter
    if (state.openOnlyFilter && f.status !== "OPEN") {
      return false;
    }

    // Keyword Search
    if (state.searchKeyword) {
      const kw = state.searchKeyword;
      const idMatch = String(f.issue_id || "").includes(kw);
      const catMatch = (f.category || "").toLowerCase().includes(kw);
      const descMatch = (f.description || "").toLowerCase().includes(kw);
      const cweMatch = (String(f.cwe_id || "") + " " + (f.cwe_name || "")).toLowerCase().includes(kw);
      const cveMatch = (f.cve_id || "").toLowerCase().includes(kw);
      const fileMatch = (f.file_path || f.file_name || "").toLowerCase().includes(kw);
      const compMatch = (f.component_filename || "").toLowerCase().includes(kw);
      const modMatch = (f.module || "").toLowerCase().includes(kw);
      const sbMatch = (f.sandbox_name || "").toLowerCase().includes(kw);
      const appMatch = (f.application_name || "").toLowerCase().includes(kw);
      const mitMatch = (f.mitigation_status || "").toLowerCase().includes(kw);

      if (!idMatch && !catMatch && !descMatch && !cweMatch && !cveMatch && !fileMatch && !compMatch && !modMatch && !sbMatch && !appMatch && !mitMatch) {
        return false;
      }
    }

    return true;
  });

  renderVulnerabilitiesTable(state.filteredFindings);
}

function setScanTypeFilter(type) {
  state.scanTypeFilter = type;

  const btnAll = document.getElementById("filterTypeAll");
  const btnSast = document.getElementById("filterTypeSast");
  const btnSca = document.getElementById("filterTypeSca");

  [btnAll, btnSast, btnSca].forEach(btn => {
    btn.className = "flex-1 py-1 rounded text-center font-medium text-slate-300 hover:text-white transition";
  });

  if (type === "ALL") {
    btnAll.className = "flex-1 py-1 rounded text-center font-medium bg-blue-600 text-white transition";
  } else if (type === "SAST") {
    btnSast.className = "flex-1 py-1 rounded text-center font-medium bg-blue-600 text-white transition";
  } else if (type === "SCA") {
    btnSca.className = "flex-1 py-1 rounded text-center font-medium bg-purple-600 text-white transition";
  }

  applyFilters();
}

// ================= EVENT HANDLERS =================

async function handleRefreshAll() {
  const icon = document.getElementById("refreshIcon");
  if (icon) icon.classList.add("fa-spin");

  try {
    await loadApplications(true);
  } finally {
    if (icon) icon.classList.remove("fa-spin");
  }
}

function handleDownloadReport(format) {
  if (state.selectedAppGuids.length === 0) {
    alert("Please select at least one application.");
    return;
  }
  if (state.selectedSandboxGuids.length === 0) {
    alert("Please select at least one sandbox to download reports.");
    return;
  }

  const appGuidsParam = encodeURIComponent(state.selectedAppGuids.join(","));
  const sbGuidsParam = encodeURIComponent(state.selectedSandboxGuids.join(","));
  let url = "";

  if (format === "excel" || format === "xlsx") {
    url = `/api/reports/excel?app_guids=${appGuidsParam}&sandbox_guids=${sbGuidsParam}`;
  } else if (format === "pdf") {
    url = `/api/reports/pdf?app_guids=${appGuidsParam}&sandbox_guids=${sbGuidsParam}`;
  } else if (format === "xml") {
    url = `/api/reports/xml?app_guids=${appGuidsParam}&sandbox_guids=${sbGuidsParam}`;
  } else {
    // CSV across all selected apps and sandboxes
    url = `/api/reports/csv?app_guids=${appGuidsParam}&sandbox_guids=${sbGuidsParam}`;
  }

  window.open(url, "_blank");
}

function clearViewNoSandboxes() {
  state.sandboxesStatusList = [];
  state.metrics = null;
  state.findings = [];
  renderScanStatuses([]);
  renderVulnerabilitiesTable([]);
  clearNativeReports();
  const kpiIds = ["kpiTotalFlaws", "kpiCritHigh", "kpiUnmitigated", "kpiMitProposed", "kpiMitApproved", "kpiSastCount", "kpiScaCount", "kpiFixed"];
  kpiIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = "0";
  });
  document.getElementById("severityMitigationMatrixTableBody").innerHTML = '<tr><td colspan="8" class="px-4 py-6 text-center text-slate-500">Select at least one application and sandbox to compute metrics.</td></tr>';
}

function setLoadingState(isLoading) {
  const tbody = document.getElementById("vulnerabilitiesTableBody");
  if (isLoading && tbody) {
    tbody.innerHTML = `
      <tr>
        <td colspan="12" class="px-4 py-8 text-center text-slate-500">
          <i class="fa-solid fa-spinner fa-spin text-xl text-blue-400 mb-2"></i>
          <div>Querying selected sandbox scans & compiling metrics...</div>
        </td>
      </tr>
    `;
  }
}

// ================= MODALS =================

function openDetailModal(flaw) {
  const modal = document.getElementById("flawDetailModal");
  if (!modal || !flaw) return;

  const typeBadge = document.getElementById("modalScanTypeBadge");
  typeBadge.textContent = flaw.scan_type;
  typeBadge.className = flaw.scan_type === "SAST" 
    ? "text-xs font-bold px-2.5 py-0.5 rounded bg-blue-900 text-blue-200 border border-blue-700"
    : "text-xs font-bold px-2.5 py-0.5 rounded bg-purple-900 text-purple-200 border border-purple-700";

  document.getElementById("modalSandboxBadge").textContent = `${flaw.application_name || 'App'} : ${flaw.sandbox_name || 'Sandbox'}`;
  
  const modBadge = document.getElementById("modalModuleBadge");
  if (modBadge) {
    modBadge.textContent = `Module: ${flaw.module || flaw.component_filename || 'N/A'}`;
  }

  document.getElementById("modalFlawTitle").textContent = flaw.category || "Vulnerability Details";
  document.getElementById("modalIssueId").textContent = `#${flaw.issue_id || 'N/A'}`;
  
  const sevEl = document.getElementById("modalSeverity");
  sevEl.innerHTML = getSeverityBadgeHtml(flaw.severity, flaw.severity_label);

  const mitEl = document.getElementById("modalMitigationStatus");
  mitEl.innerHTML = getMitigationBadgeHtml(flaw.mitigation_status);

  document.getElementById("modalFirstFound").textContent = formatDate(flaw.first_found_date);

  // Security Standard (CWE or CVE)
  const advText = document.getElementById("modalAdvisoryText");
  if (flaw.scan_type === "SAST") {
    advText.textContent = `CWE-${flaw.cwe_id || 'Unknown'}: ${flaw.cwe_name || flaw.category || 'Static Code Flaw'}`;
  } else {
    advText.textContent = `${flaw.cve_id || 'Component Advisory'} (CVSS: ${flaw.cvss || 'N/A'})`;
  }

  // Location
  const locText = document.getElementById("modalLocationText");
  if (flaw.scan_type === "SAST") {
    locText.textContent = flaw.file_path 
      ? `${flaw.file_path}${flaw.line_number ? ` : Line ${flaw.line_number}` : ''}`
      : "Path not specified";
  } else {
    locText.textContent = `Component: ${flaw.component_filename || 'Unknown'} (Version: ${flaw.version || 'N/A'})`;
  }

  document.getElementById("modalDescription").textContent = flaw.description || "No expanded description reported by engine.";
  document.getElementById("modalRemediation").textContent = flaw.remediation_advice || "Apply latest patches or adhere to OWASP / Veracode mitigation standards.";

  modal.classList.remove("hidden");
}

function closeDetailModal() {
  const modal = document.getElementById("flawDetailModal");
  if (modal) modal.classList.add("hidden");
}

function openSettingsModal() {
  const modal = document.getElementById("settingsModal");
  if (!modal) return;

  const testBox = document.getElementById("testOutputBox");
  if (testBox) testBox.classList.add("hidden");

  if (state.systemStatus) {
    document.getElementById("selectRegion").value = state.systemStatus.region || "us";
  }

  modal.classList.remove("hidden");
}

function closeSettingsModal() {
  const modal = document.getElementById("settingsModal");
  if (modal) modal.classList.add("hidden");
}

async function handleTestConnection() {
  const apiId = document.getElementById("inputApiId").value.trim();
  const apiSecret = document.getElementById("inputApiSecret").value.trim();
  const region = document.getElementById("selectRegion").value;
  const testBox = document.getElementById("testOutputBox");

  testBox.classList.remove("hidden");
  testBox.className = "p-3 rounded-xl text-xs font-mono bg-slate-950 border border-slate-700 text-slate-300";
  testBox.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1.5 text-cyan-400"></i> Testing HMAC-SHA256 handshake with Veracode...';

  try {
    let res;
    if (apiId && apiSecret) {
      res = await fetch("/api/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ api_id: apiId, api_secret: apiSecret, region: region })
      });
    } else {
      res = await fetch("/api/config/test", { method: "POST" });
    }

    const data = await res.json();
    if (data.success) {
      testBox.className = "p-3 rounded-xl text-xs font-mono bg-emerald-950/60 border border-emerald-800 text-emerald-300";
      testBox.innerHTML = `<i class="fa-solid fa-circle-check mr-1.5 text-emerald-400"></i> ${escapeHtml(data.message)}`;
    } else {
      testBox.className = "p-3 rounded-xl text-xs font-mono bg-red-950/60 border border-red-800 text-red-300";
      testBox.innerHTML = `<i class="fa-solid fa-circle-xmark mr-1.5 text-red-400"></i> ${escapeHtml(data.message)}`;
    }
  } catch (err) {
    testBox.className = "p-3 rounded-xl text-xs font-mono bg-red-950/60 border border-red-800 text-red-300";
    testBox.innerHTML = `<i class="fa-solid fa-triangle-exclamation mr-1.5"></i> Request failed: ${escapeHtml(err.message)}`;
  }
}

async function handleSaveCredentials() {
  const apiId = document.getElementById("inputApiId").value.trim();
  const apiSecret = document.getElementById("inputApiSecret").value.trim();
  const region = document.getElementById("selectRegion").value;

  if (!apiId || !apiSecret) {
    alert("Please provide both Veracode API ID and API Secret Key.");
    return;
  }

  try {
    const res = await fetch("/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ api_id: apiId, api_secret: apiSecret, region: region })
    });

    const data = await res.json();
    if (data.status) {
      state.systemStatus = data.status;
      updateConnectionBadge(state.systemStatus);
    }

    closeSettingsModal();
    await loadApplications(true);
  } catch (err) {
    alert("Failed to save credentials: " + err.message);
  }
}

async function handleEnableMockMode() {
  try {
    const res = await fetch("/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ use_mock: true })
    });
    const data = await res.json();
    if (data.status) {
      state.systemStatus = data.status;
      updateConnectionBadge(state.systemStatus);
    }
    closeSettingsModal();
    await loadApplications(true);
  } catch (err) {
    alert("Failed to enable mock mode: " + err.message);
  }
}

// ================= UTILITY HELPERS =================

function formatDate(isoStr) {
  if (!isoStr) return "N/A";
  try {
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return isoStr;
    return d.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric"
    });
  } catch {
    return isoStr;
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ================= VERACODE NATIVE REPORTS =================

async function loadVericodeReportInfo() {
  if (state.selectedAppGuids.length === 0 || state.selectedSandboxGuids.length === 0) {
    clearNativeReports();
    return;
  }
  try {
    const appP = encodeURIComponent(state.selectedAppGuids.join(","));
    const sbP  = encodeURIComponent(state.selectedSandboxGuids.join(","));
    const res  = await fetch(`/api/veracode/report/info?app_guids=${appP}&sandbox_guids=${sbP}`);
    if (!res.ok) { clearNativeReports(); return; }
    const data = await res.json();
    renderNativeReports(data);
  } catch (e) {
    console.warn("Veracode report info fetch failed:", e);
    clearNativeReports();
  }
}

function renderNativeReports(data) {
  const panel   = document.getElementById("nativeReportsPanel");
  const list    = document.getElementById("nativeReportsList");
  const pdfBadge = document.getElementById("pdfSourceBadge");
  const xmlBadge = document.getElementById("xmlSourceBadge");

  if (!data || !data.is_live || !data.veracode_reports_available) {
    clearNativeReports();
    return;
  }

  // Show Veracode source badges on the main download buttons
  if (pdfBadge) pdfBadge.classList.remove("hidden");
  if (xmlBadge) xmlBadge.classList.remove("hidden");

  panel.classList.remove("hidden");
  list.innerHTML = "";

  const sandboxes = data.sandboxes || [];
  const available = sandboxes.filter(sb => sb.veracode_report_available);

  if (available.length === 0) {
    list.innerHTML = '<div class="col-span-full text-center text-slate-500 text-xs py-4">No build IDs resolved for the selected sandboxes.</div>';
    return;
  }

  available.forEach(sb => {
    const card = document.createElement("div");
    card.className = "bg-slate-900/80 border border-slate-700 rounded-xl p-3 space-y-2";
    card.innerHTML = `
      <div class="text-[11px] font-semibold text-slate-200 truncate" title="${escapeHtml(sb.sandbox_name)}">${escapeHtml(sb.sandbox_name)}</div>
      <div class="text-[10px] text-slate-400 font-mono">Build ID: <span class="text-cyan-400">${escapeHtml(String(sb.build_id))}</span></div>
      <div class="flex gap-2">
        <a href="${escapeHtml(sb.pdf_url)}" target="_blank"
           class="flex-1 text-center text-[10px] font-bold bg-rose-900/60 hover:bg-rose-800 text-rose-200 border border-rose-700 px-2 py-1.5 rounded-lg transition">
          <i class="fa-solid fa-file-pdf mr-1"></i>PDF
        </a>
        <a href="${escapeHtml(sb.xml_url)}" target="_blank"
           class="flex-1 text-center text-[10px] font-bold bg-cyan-900/60 hover:bg-cyan-800 text-cyan-200 border border-cyan-700 px-2 py-1.5 rounded-lg transition">
          <i class="fa-solid fa-file-code mr-1"></i>XML
        </a>
      </div>
    `;
    list.appendChild(card);
  });
}

function clearNativeReports() {
  const panel    = document.getElementById("nativeReportsPanel");
  const pdfBadge = document.getElementById("pdfSourceBadge");
  const xmlBadge = document.getElementById("xmlSourceBadge");
  if (panel)    panel.classList.add("hidden");
  if (pdfBadge) pdfBadge.classList.add("hidden");
  if (xmlBadge) xmlBadge.classList.add("hidden");
}
