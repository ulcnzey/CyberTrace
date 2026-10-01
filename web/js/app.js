const state = {
  route: "overview",
  sessionId: sessionStorage.getItem("cybertrace-session") || "",
  sessions: [],
  socket: null,
  liveFeed: [],
  liveStats: null,
};

const routes = ["overview", "live", "pcap", "alerts", "hosts", "iocs", "timeline", "reports", "settings"];

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return esc(value);
  return date.toLocaleString();
}

function formatBytes(value) {
  const size = Number(value) || 0;
  if (size < 1024) return `${size} B`;
  if (size < 1048576) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1048576).toFixed(1)} MB`;
}

function formatConfidence(value) {
  return `${Math.round(Number(value) * 100)}%`;
}

async function api(path, options) {
  const response = await fetch(path, options);
  const text = await response.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { detail: text };
    }
  }
  if (!response.ok) {
    const detail = body && body.detail;
    throw new Error(typeof detail === "string" ? detail : "Request failed");
  }
  return body;
}

function badge(severity) {
  const name = severity || "info";
  return `<span class="badge ${esc(name)}">${esc(name)}</span>`;
}

function endpoint(row) {
  const src = row.src_ip ? `${row.src_ip}${row.src_port ? ":" + row.src_port : ""}` : "—";
  const dst = row.dst_ip ? `${row.dst_ip}${row.dst_port ? ":" + row.dst_port : ""}` : "—";
  return `${esc(src)} → ${esc(dst)}`;
}

function setSession(id) {
  state.sessionId = id ? String(id) : "";
  if (state.sessionId) sessionStorage.setItem("cybertrace-session", state.sessionId);
  else sessionStorage.removeItem("cybertrace-session");
  const select = document.getElementById("session-select");
  if (select) select.value = state.sessionId;
}

async function loadSessions() {
  const payload = await api("/api/analyses");
  state.sessions = payload.items || [];
  if (!state.sessionId && state.sessions.length) setSession(state.sessions[0].id);
  if (state.sessionId && !state.sessions.some((item) => String(item.id) === state.sessionId)) {
    setSession(state.sessions[0] ? state.sessions[0].id : "");
  }
  const select = document.getElementById("session-select");
  select.innerHTML = state.sessions.length
    ? state.sessions.map((item) => `<option value="${item.id}">${esc(item.name)} · ${esc(item.status)}</option>`).join("")
    : `<option value="">No analysis yet</option>`;
  select.value = state.sessionId;
}

function requireSession() {
  if (!state.sessionId) {
    return `<p class="empty">Analyze a PCAP or start a live capture to fill this view.</p>`;
  }
  return "";
}

async function renderOverview() {
  const query = state.sessionId ? `?session_id=${encodeURIComponent(state.sessionId)}` : "";
  const data = await api(`/api/overview${query}`);
  const stats = data.stats || {};
  const severity = data.severity || {};
  const maxSeverity = Math.max(1, ...Object.values(severity));
  const severityRows = ["critical", "high", "medium", "low", "info"].map((name) => {
    const count = severity[name] || 0;
    const width = Math.round((count / maxSeverity) * 100);
    return `<div><span>${esc(name)}</span><i class="${esc(name)}"><b style="width:${width}%"></b></i><strong>${count}</strong></div>`;
  }).join("");
  const events = (data.recent_events || []).map((event) => `
    <li>
      <small>${esc(event.event_type)} · ${formatTime(event.occurred_at)}</small>
      <span>${esc(event.summary)}</span>
    </li>`).join("") || `<li><span class="empty">Security events appear here after an analysis.</span></li>`;
  const protocols = Object.entries(data.protocols || {}).map(([name, count]) => `<span>${esc(name)} ${count}</span>`).join("");
  document.getElementById("view").innerHTML = `
    <section class="hero">
      <p class="eyebrow">Network security monitoring</p>
      <h1>See what your network sees.</h1>
      <p class="lede">${esc(data.notice || "")}</p>
      <div class="actions">
        <a class="button" href="#pcap">Analyze PCAP</a>
        <a class="button secondary" href="#live">Live Monitoring</a>
      </div>
      <ol class="pipeline">
        <li>Capture</li><li>Analyze</li><li>Detect</li><li>Understand</li><li>Respond</li>
      </ol>
    </section>
    <section class="stats">
      <article class="stat"><span>Packets</span><strong>${stats.packets || 0}</strong></article>
      <article class="stat"><span>Connections</span><strong>${stats.connections || 0}</strong></article>
      <article class="stat"><span>Hosts</span><strong>${stats.hosts || 0}</strong></article>
      <article class="stat"><span>Alerts</span><strong>${stats.alerts || 0}</strong></article>
    </section>
    <section class="grid-2">
      <article class="panel">
        <h2>Traffic</h2>
        ${trafficChart(data.traffic || [])}
        <div class="protocols">${protocols}</div>
      </article>
      <article class="panel">
        <h2>Severity</h2>
        <div class="severity">${severityRows}</div>
      </article>
    </section>
    <section class="grid-2" style="margin-top:14px">
      <article class="panel">
        <h2>Network activity</h2>
        ${topologyMarkup(data.topology || { nodes: [], links: [] })}
      </article>
      <article class="panel">
        <h2>Recent security events</h2>
        <ul class="events">${events}</ul>
      </article>
    </section>`;
}

function trafficChart(buckets) {
  if (!buckets.length) return `<p class="empty">No packets in the selected analysis.</p>`;
  const width = 640;
  const height = 180;
  const max = Math.max(...buckets.map((bucket) => bucket.packets), 1);
  const gap = 10;
  const barWidth = Math.max(8, (width - gap * buckets.length) / buckets.length);
  const bars = buckets.map((bucket, index) => {
    const barHeight = Math.max(3, (bucket.packets / max) * (height - 16));
    const x = index * (barWidth + gap);
    const y = height - barHeight;
    return `<rect x="${x}" y="${y}" width="${barWidth}" height="${barHeight}" rx="5"><title>${bucket.packets} packets</title></rect>`;
  }).join("");
  return `<svg class="chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="Packets across the capture">${bars}</svg>`;
}

function topologyMarkup(topology) {
  const nodes = topology.nodes || [];
  if (!nodes.length) {
    return `<svg class="topology" viewBox="0 0 640 220" aria-hidden="true">
      <line x1="120" y1="110" x2="320" y2="60"></line>
      <line x1="320" y1="60" x2="500" y2="130"></line>
      <line x1="180" y1="170" x2="320" y2="60"></line>
      <circle cx="120" cy="110" r="7"></circle>
      <circle cx="320" cy="60" r="7"></circle>
      <circle cx="500" cy="130" r="7"></circle>
      <circle cx="180" cy="170" r="7"></circle>
    </svg><p class="empty">Topology appears after a capture. This sketch is not live traffic.</p>`;
  }
  const width = 640;
  const height = 240;
  const placed = nodes.map((node, index) => {
    const angle = (Math.PI * 2 * index) / nodes.length - Math.PI / 2;
    return {
      ...node,
      x: width / 2 + Math.cos(angle) * 180,
      y: height / 2 + Math.sin(angle) * 80,
    };
  });
  const byId = Object.fromEntries(placed.map((node) => [node.id, node]));
  const lines = (topology.links || []).map((link) => {
    const source = byId[link.source];
    const target = byId[link.target];
    if (!source || !target) return "";
    return `<line x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}"></line>`;
  }).join("");
  const circles = placed.map((node) => `
    <circle cx="${node.x}" cy="${node.y}" r="8"></circle>
    <text x="${node.x + 12}" y="${node.y + 4}">${esc(node.ip)}</text>`).join("");
  return `<svg class="topology" viewBox="0 0 ${width} ${height}" role="img" aria-label="Hosts observed in the analysis">${lines}${circles}</svg>`;
}

async function renderPcap() {
  document.getElementById("view").innerHTML = `
    <div class="page-head"><div><h1>PCAP analysis</h1><p>Upload a PCAP or PCAPNG from a network you are allowed to examine. The file is deleted after parsing.</p></div></div>
    <section class="panel">
      <div class="drop" id="drop">
        <h2>Drop a capture</h2>
        <p>or choose a .pcap / .pcapng file</p>
        <input id="pcap-file" type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap">
        <p class="message" id="upload-message"></p>
      </div>
    </section>
    <section class="panel" style="margin-top:14px">
      <h2>Recent analyses</h2>
      ${sessionTable()}
    </section>`;
  const input = document.getElementById("pcap-file");
  const drop = document.getElementById("drop");
  input.addEventListener("change", () => { if (input.files[0]) uploadFile(input.files[0]); });
  drop.addEventListener("dragover", (event) => { event.preventDefault(); drop.classList.add("hot"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("hot"));
  drop.addEventListener("drop", (event) => {
    event.preventDefault();
    drop.classList.remove("hot");
    if (event.dataTransfer.files[0]) uploadFile(event.dataTransfer.files[0]);
  });
}

async function uploadFile(file) {
  const message = document.getElementById("upload-message");
  message.textContent = "Analyzing capture…";
  const body = new FormData();
  body.append("file", file);
  try {
    const result = await api("/api/analyses/pcap", { method: "POST", body });
    setSession(result.id);
    await loadSessions();
    message.textContent = `Finished ${result.name}. ${result.alert_count} alerts from ${result.packet_count} packets.`;
  } catch (error) {
    message.textContent = error.message;
  }
}

function sessionTable() {
  if (!state.sessions.length) return `<p class="empty">No analyses yet.</p>`;
  const rows = state.sessions.map((item) => `
    <tr>
      <td>${esc(item.name)}</td>
      <td>${esc(item.source_type)}</td>
      <td>${esc(item.status)}</td>
      <td>${item.packet_count}</td>
      <td>${item.alert_count}</td>
      <td><button class="button secondary" data-open="${item.id}" type="button">Open</button></td>
    </tr>`).join("");
  return `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Source</th><th>Status</th><th>Packets</th><th>Alerts</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

async function renderAlerts() {
  const missing = requireSession();
  let body = missing;
  if (!missing) {
    const payload = await api(`/api/analyses/${state.sessionId}/alerts`);
    body = alertTable(payload.items || []);
  }
  document.getElementById("view").innerHTML = `
    <div class="page-head"><div><h1>Alerts</h1><p>Severity describes impact. Confidence describes how strongly the evidence matched. They are separate.</p></div></div>
    <section class="panel">${body}</section>`;
}

function alertTable(items) {
  if (!items.length) return `<p class="empty">No alerts for this analysis.</p>`;
  const rows = items.map((alert) => `
    <tr>
      <td>${badge(alert.severity)}</td>
      <td>${formatConfidence(alert.confidence)}</td>
      <td>${esc(alert.name)}<div class="meta">${esc(alert.detector_id)}</div></td>
      <td>${endpoint(alert)}<div class="meta">${esc(alert.protocol || "")}</div></td>
      <td>${formatTime(alert.observed_at)}</td>
      <td class="evidence">${esc(alert.evidence)}<div class="meta">${esc(alert.recommended_action || "")}</div></td>
    </tr>`).join("");
  return `<div class="table-wrap"><table>
    <thead><tr><th>Severity</th><th>Confidence</th><th>Detection</th><th>Source / destination</th><th>Time</th><th>Evidence</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

async function renderHosts() {
  const missing = requireSession();
  let body = missing;
  if (!missing) {
    const payload = await api(`/api/analyses/${state.sessionId}/hosts`);
    const items = payload.items || [];
    body = items.length ? `<div class="table-wrap"><table><thead><tr><th>Host</th><th>Role</th><th>MAC</th><th>Sent</th><th>Received</th></tr></thead><tbody>
      ${items.map((host) => `<tr><td>${esc(host.ip)}</td><td>${esc(host.role)}</td><td>${esc((host.macs || []).join(", ") || "—")}</td><td>${formatBytes(host.bytes_sent)}</td><td>${formatBytes(host.bytes_received)}</td></tr>`).join("")}
    </tbody></table></div>` : `<p class="empty">No hosts in this analysis.</p>`;
  }
  document.getElementById("view").innerHTML = `<div class="page-head"><div><h1>Hosts</h1><p>Addresses summarized from stored flows, not from a packet archive.</p></div></div><section class="panel">${body}</section>`;
}

async function renderIocs() {
  const missing = requireSession();
  let body = missing;
  if (!missing) {
    const payload = await api(`/api/analyses/${state.sessionId}/iocs`);
    const items = payload.items || [];
    const labels = { ip: "IP", mac: "MAC", domain: "Domain", url: "URL", port: "Port", user_agent: "User-Agent", timestamp: "Timestamp" };
    body = items.length ? `<div class="table-wrap"><table><thead><tr><th>Type</th><th>Value</th><th>Observed</th></tr></thead><tbody>
      ${items.map((item) => `<tr><td>${esc(labels[item.indicator_type] || item.indicator_type)}</td><td>${esc(item.value)}</td><td>${formatTime(item.observed_at)}</td></tr>`).join("")}
    </tbody></table></div>` : `<p class="empty">No indicators were extracted from the alerts in this analysis.</p>`;
  }
  document.getElementById("view").innerHTML = `<div class="page-head"><div><h1>Indicators</h1><p>IPs, MACs, domains, URLs, ports, user agents, and timestamps tied to detections.</p></div></div><section class="panel">${body}</section>`;
}

async function renderTimeline() {
  const missing = requireSession();
  let body = missing;
  if (!missing) {
    const payload = await api(`/api/analyses/${state.sessionId}/timeline`);
    const items = payload.items || [];
    body = items.length ? `<ol class="timeline">${items.map((item) => `<li><div class="meta">${formatTime(item.occurred_at)} · ${esc(item.event_type)}</div><div>${esc(item.summary)}</div></li>`).join("")}</ol>` : `<p class="empty">No timeline events.</p>`;
  }
  document.getElementById("view").innerHTML = `<div class="page-head"><div><h1>Timeline</h1><p>Analysis boundaries, protocol observations, detections, and alerts in order.</p></div></div><section class="panel">${body}</section>`;
}

async function renderReports() {
  const missing = requireSession();
  let summary = missing || `<p class="empty">Loading analysis…</p>`;
  document.getElementById("view").innerHTML = `
    <div class="page-head"><div><h1>Reports</h1><p>JSON and PDF are generated from the stored analysis.</p></div></div>
    <section class="panel" id="report-panel">${summary}</section>`;
  if (missing) return;
  try {
    const detail = await api(`/api/analyses/${state.sessionId}`);
    document.getElementById("report-panel").innerHTML = `
      <h2>${esc(detail.name)}</h2>
      <p class="quiet">${esc(detail.status)} · ${detail.packet_count} packets · ${detail.alert_count} alerts</p>
      <p>${esc(detail.warning || "Raw packets were not kept.")}</p>
      <div class="actions">
        <a class="button" href="/api/analyses/${detail.id}/reports/json">Download JSON</a>
        <a class="button secondary" href="/api/analyses/${detail.id}/reports/pdf">Download PDF</a>
      </div>`;
  } catch (error) {
    document.getElementById("report-panel").innerHTML = `<p class="empty">${esc(error.message)}</p>`;
  }
}

async function renderSettings() {
  const settings = await api("/api/settings");
  document.getElementById("view").innerHTML = `
    <div class="page-head"><div><h1>Settings</h1><p>Limits for this local installation.</p></div></div>
    <section class="panel stack">
      <p>${esc(settings.notice)}</p>
      <p class="quiet">Upload limit ${formatBytes(settings.max_upload_bytes)} · PCAP packet cap ${settings.max_packets} · Live packet cap ${settings.live_max_packets} · Live duration up to ${settings.live_max_duration} seconds.</p>
      <p class="${settings.capture_available ? "quiet" : "callout"}">${esc(settings.capture_message)}</p>
    </section>`;
}

function closeSocket() {
  if (state.socket) {
    state.socket.close();
    state.socket = null;
  }
}

async function renderLive() {
  closeSocket();
  const info = await api("/api/interfaces");
  const status = await api("/api/live/status");
  const options = (info.interfaces || []).map((item) => `<option value="${esc(item.name)}">${esc(item.description)}</option>`).join("");
  document.getElementById("view").innerHTML = `
    <div class="page-head"><div><h1>Live monitoring</h1><p>Watch an interface you are permitted to capture. Detections use the same engine as PCAP analysis.</p></div></div>
    <section class="live-layout">
      <article class="panel">
        <h2>Capture</h2>
        <p class="${info.available ? "quiet" : "callout"}">${esc(info.message)}</p>
        <label class="field">Interface<select id="iface" ${info.available ? "" : "disabled"}>${options || `<option value="">No interface</option>`}</select></label>
        <label class="field">Duration (seconds)<input id="duration" type="number" min="5" max="300" value="60"></label>
        <div class="actions">
          <button class="button" id="start-live" type="button" ${info.available ? "" : "disabled"}>Start</button>
          <button class="button secondary" id="stop-live" type="button">Stop</button>
        </div>
        <p class="message" id="live-message">${status.running ? "A capture is already running." : ""}</p>
      </article>
      <article class="panel">
        <h2>Activity</h2>
        <div class="counters" id="live-counters">
          <div><span>Packets</span><strong id="count-packets">0</strong></div>
          <div><span>Connections</span><strong id="count-flows">0</strong></div>
          <div><span>Alerts</span><strong id="count-alerts">0</strong></div>
        </div>
        <div class="protocols" id="live-protocols"></div>
        <div class="feed" id="live-feed"></div>
      </article>
    </section>`;
  document.getElementById("start-live").addEventListener("click", startLive);
  document.getElementById("stop-live").addEventListener("click", stopLive);
  if (status.running && status.session_id) connectLive(status.session_id);
}

async function startLive() {
  const message = document.getElementById("live-message");
  message.textContent = "Starting capture…";
  try {
    const result = await api("/api/live/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        interface: document.getElementById("iface").value,
        duration_seconds: Number(document.getElementById("duration").value || 60),
      }),
    });
    setSession(result.id);
    await loadSessions();
    state.liveFeed = [];
    message.textContent = result.error_message || "Capture is running.";
    connectLive(result.id);
  } catch (error) {
    message.textContent = error.message;
  }
}

async function stopLive() {
  const message = document.getElementById("live-message");
  try {
    await api("/api/live/stop", { method: "POST" });
    message.textContent = "Capture stopped.";
    await loadSessions();
  } catch (error) {
    message.textContent = error.message;
  }
}

function connectLive(sessionId) {
  closeSocket();
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${protocol}://${location.host}/ws/live/${sessionId}`);
  state.socket = socket;
  socket.addEventListener("message", (event) => {
    let payload = null;
    try { payload = JSON.parse(event.data); } catch { return; }
    if (payload.type === "stats") {
      const packets = document.getElementById("count-packets");
      const flows = document.getElementById("count-flows");
      const alerts = document.getElementById("count-alerts");
      if (packets) packets.textContent = payload.packet_count ?? 0;
      if (flows) flows.textContent = payload.connections ?? 0;
      if (alerts) alerts.textContent = payload.alerts ?? 0;
      const protocols = document.getElementById("live-protocols");
      if (protocols) {
        protocols.innerHTML = Object.entries(payload.protocols || {}).map(([name, count]) => `<span>${esc(name)} ${count}</span>`).join("");
      }
    }
    if (payload.type === "alert" || payload.type === "detection" || payload.type === "status") {
      const text = payload.detail || (payload.alert && payload.alert.name) || (payload.detection && payload.detection.name) || payload.status;
      state.liveFeed.unshift({ kind: payload.type, text });
      state.liveFeed = state.liveFeed.slice(0, 30);
      const feed = document.getElementById("live-feed");
      if (feed) {
        feed.innerHTML = state.liveFeed.map((item) => `<article><div class="meta">${esc(item.kind)}</div><div>${esc(item.text)}</div></article>`).join("");
      }
      if (payload.type === "status" && payload.detail) {
        const message = document.getElementById("live-message");
        if (message) message.textContent = payload.detail;
      }
    }
  });
}

async function render() {
  const route = routes.includes(state.route) ? state.route : "overview";
  document.querySelectorAll(".nav a[data-route]").forEach((link) => {
    if (link.dataset.route === route) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  if (route !== "live") closeSocket();
  const view = document.getElementById("view");
  view.innerHTML = `<p class="empty">Loading…</p>`;
  try {
    await loadSessions();
    const pages = { overview: renderOverview, live: renderLive, pcap: renderPcap, alerts: renderAlerts, hosts: renderHosts, iocs: renderIocs, timeline: renderTimeline, reports: renderReports, settings: renderSettings };
    await pages[route]();
    document.querySelectorAll("[data-open]").forEach((button) => {
      button.addEventListener("click", async () => {
        setSession(button.dataset.open);
        location.hash = "alerts";
      });
    });
  } catch (error) {
    view.innerHTML = `<p class="callout">${esc(error.message)}</p>`;
  }
}

function syncRoute() {
  state.route = (location.hash || "#overview").slice(1) || "overview";
  render();
}

document.getElementById("session-select").addEventListener("change", (event) => {
  setSession(event.target.value);
  render();
});

async function refreshHealth() {
  const node = document.getElementById("health");
  try {
    const body = await api("/health");
    const ok = body.status === "ok" && body.database === "ok";
    node.innerHTML = `<span class="dot ${ok ? "ok" : "bad"}"></span><span>${ok ? "API and database ready" : "Database unavailable"}</span>`;
  } catch {
    node.innerHTML = `<span class="dot bad"></span><span>API unreachable</span>`;
  }
}

window.addEventListener("hashchange", syncRoute);
refreshHealth();
syncRoute();
