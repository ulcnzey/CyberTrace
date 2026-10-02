import { t, initI18n, setLanguage, onLanguage, language, applyChrome, knownPhrase } from "./i18n.js?v=13";
import { api } from "./api.js?v=12";

const state = {
  route: "overview",
  sessionId: sessionStorage.getItem("cybertrace-session") || "",
  sessions: [],
  settings: null,
  socket: null,
  liveFeed: [],
  liveSeries: [],
  ppsSample: null,
  mapAt: 0,
  chartMode: "packets",
  cache: {},
  filters: { alerts: "", hosts: "", iocs: "", iocType: "all", timelineType: "all", timelineSeverity: "all", timelineSource: "", timelineDest: "", timelineProtocol: "" },
  sort: {},
  pcapTab: "traffic",
  highlightIp: "",
  pages: {},
};

const routes = ["overview", "live", "pcap", "alerts", "hosts", "iocs", "timeline", "reports", "settings"];
const severityRank = { info: 1, low: 2, medium: 3, high: 4, critical: 5 };

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatTime(value) {
  if (!value) return t("common.notObserved");
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return esc(value);
  const locale = { tr: "tr-TR", en: "en-GB", ar: "ar-SA" }[language()] || "en-GB";
  return date.toLocaleString(locale);
}

function formatBytes(value) {
  const size = Number(value);
  if (!Number.isFinite(size)) return t("common.notObserved");
  if (size < 1024) return `${size} B`;
  if (size < 1048576) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1048576).toFixed(1)} MB`;
}

function formatConfidence(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return t("common.notObserved");
  return `${Math.round(number * 100)}%`;
}

function motionOk() {
  return !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function badge(severity) {
  const name = severity || "info";
  const label = t(`severity.${name}`);
  return `<span class="badge ${esc(name)}">${esc(label === `severity.${name}` ? name : label)}</span>`;
}

function statusLabel(value) {
  if (!value) return t("common.notObserved");
  const label = t(`session.${value}`);
  return label === `session.${value}` ? value : label;
}

function roleLabel(value) {
  if (!value) return t("roles.observed");
  const label = t(`roles.${value}`);
  return label === `roles.${value}` ? value : label;
}

function eventLabel(value) {
  if (!value) return "";
  const label = t(`events.${value}`);
  return label === `events.${value}` ? value : label;
}

function emptyBlock(title, detail) {
  return `<div class="empty"><div><strong class="empty-title">${esc(title)}</strong><span>${esc(detail)}</span></div></div>`;
}

function countUp(el, value) {
  const target = Number(value);
  if (!el || !Number.isFinite(target)) return;
  const paint = () => { if (el.isConnected) el.textContent = String(target); };
  if (!motionOk() || document.hidden) {
    paint();
    return;
  }
  const start = performance.now();
  const finish = setTimeout(paint, 700);
  const tick = (now) => {
    if (!el.isConnected) return;
    const progress = Math.min(1, (now - start) / 650);
    const eased = 1 - (1 - progress) ** 3;
    el.textContent = String(Math.round(target * eased));
    if (progress < 1) requestAnimationFrame(tick);
    else clearTimeout(finish);
  };
  requestAnimationFrame(tick);
}

function setSession(id) {
  const next = id ? String(id) : "";
  if (next !== state.sessionId) state.cache = {};
  state.sessionId = next;
  if (state.sessionId) sessionStorage.setItem("cybertrace-session", state.sessionId);
  else sessionStorage.removeItem("cybertrace-session");
  const select = document.getElementById("session-select");
  if (select) select.value = state.sessionId;
  paintSessionChip();
}

function paintSessionChip() {
  const chip = document.getElementById("session-chip");
  if (!chip) return;
  const session = state.sessions.find((item) => String(item.id) === state.sessionId);
  chip.textContent = session ? `${session.name} · ${statusLabel(session.status)}` : t("session.none");
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
    ? state.sessions.map((item) => `<option value="${item.id}">${esc(item.name)} · ${esc(statusLabel(item.status))}</option>`).join("")
    : `<option value="">${esc(t("session.none"))}</option>`;
  select.value = state.sessionId;
  paintSessionChip();
}

async function bundle() {
  if (!state.sessionId) return null;
  if (state.cache.bundle && state.cache.bundleId === state.sessionId) return state.cache.bundle;
  const id = encodeURIComponent(state.sessionId);
  const [detail, hosts, flows, alerts, iocs, timeline] = await Promise.all([
    api(`/api/analyses/${id}`),
    api(`/api/analyses/${id}/hosts`),
    api(`/api/analyses/${id}/flows`),
    api(`/api/analyses/${id}/alerts`),
    api(`/api/analyses/${id}/iocs`),
    api(`/api/analyses/${id}/timeline`),
  ]);
  const flowItems = flows.items || [];
  const alertItems = alerts.items || [];
  const data = {
    detail,
    hosts: enrichHosts(hosts.items || [], flowItems, alertItems),
    flows: flowItems,
    flowTotal: flows.total || 0,
    flowTruncated: Boolean(flows.truncated),
    alerts: alertItems,
    iocs: iocs.items || [],
    threatIntel: iocs.threat_intel || { status: "unavailable", reputation: null },
    timeline: timeline.items || [],
  };
  state.cache.bundle = data;
  state.cache.bundleId = state.sessionId;
  state.cache.alerts = data.alerts;
  state.cache.hosts = data.hosts;
  state.cache.timeline = data.timeline;
  return data;
}

function enrichHosts(hosts, flows, alerts) {
  return hosts.map((host) => {
    const related = flows.filter((flow) => flow.src_ip === host.ip || flow.dst_ip === host.ip);
    const hostAlerts = alerts.filter((alert) => alert.src_ip === host.ip || alert.dst_ip === host.ip);
    const derivedProtocols = [...new Set(related.map((flow) => flow.protocol).filter(Boolean))];
    const times = related.flatMap((flow) => [flow.started_at, flow.ended_at].filter(Boolean));
    const derivedPorts = new Set();
    related.forEach((flow) => {
      if (flow.src_ip === host.ip && flow.src_port != null) derivedPorts.add(flow.src_port);
      if (flow.dst_ip === host.ip && flow.dst_port != null) derivedPorts.add(flow.dst_port);
    });
    return {
      ...host,
      packets: Number(host.packet_count ?? (Number(host.packets_sent || 0) + Number(host.packets_received || 0))),
      bytes: Number(host.bytes_sent || 0) + Number(host.bytes_received || 0),
      protocols: host.protocols && host.protocols.length ? host.protocols : derivedProtocols,
      connections: related.length,
      alertCount: hostAlerts.length,
      first_seen: host.first_seen || (times.length ? times.reduce((left, right) => (left < right ? left : right)) : null),
      last_seen: host.last_seen || (times.length ? times.reduce((left, right) => (left > right ? left : right)) : null),
      ports: host.ports && host.ports.length ? host.ports : [...derivedPorts].sort((a, b) => a - b),
      relatedFlows: related,
      relatedAlerts: hostAlerts,
    };
  });
}

function hostSeverity(ip, alerts) {
  let best = "";
  let rank = 0;
  (alerts || []).forEach((alert) => {
    if (alert.src_ip !== ip && alert.dst_ip !== ip) return;
    const score = severityRank[alert.severity] || 0;
    if (score > rank) {
      rank = score;
      best = alert.severity;
    }
  });
  return best;
}

function macFor(hosts, ip) {
  const host = (hosts || []).find((item) => item.ip === ip);
  if (!host || !host.macs || !host.macs.length) return "";
  return host.macs.join(", ");
}

function sortRows(items, table) {
  const sorting = state.sort[table];
  if (!sorting) return items.slice();
  const { key, dir } = sorting;
  return items.slice().sort((left, right) => {
    const a = left[key];
    const b = right[key];
    if (typeof a === "number" && typeof b === "number") return (a - b) * dir;
    return String(a ?? "").localeCompare(String(b ?? "")) * dir;
  });
}

function matches(query, values) {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  return values.some((value) => String(value ?? "").toLowerCase().includes(needle));
}

function skeleton() {
  return `<div class="skeleton-grid"><div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div><div class="skeleton tall"></div><div class="skeleton tall"></div></div>`;
}

function infoTip(concept) {
  if (!concept) return "";
  const name = t(`learn.concepts.${concept}.name`);
  const text = t(`learn.concepts.${concept}.text`);
  if (!text || text === `learn.concepts.${concept}.text`) return "";
  return `<button type="button" class="info-tip" aria-label="${esc(name)}" data-tip="${esc(text)}"><span aria-hidden="true">ⓘ</span></button>`;
}

function conceptForDetector(id) {
  return {
    beaconing: "beaconing",
    horizontal_port_scan: "portScan",
    vertical_port_scan: "portScan",
    network_scan: "portScan",
    syn_burst: "syn",
    dns_anomaly: "dnsAnomaly",
    arp_multi_mac: "arp",
    http_anomaly: "http",
    icmp_anomaly: "icmp",
  }[id] || "";
}

function conceptForProtocol(name) {
  const key = String(name || "").toLowerCase();
  return ["tcp", "udp", "dns", "http", "tls", "arp", "icmp"].includes(key) ? key : "";
}

function orderedBuckets(buckets) {
  return (buckets || [])
    .map((bucket) => ({
      offset: Number(bucket.offset_seconds),
      packets: Number(bucket.packets) || 0,
      bytes: Number(bucket.bytes) || 0,
    }))
    .filter((bucket) => Number.isFinite(bucket.offset))
    .sort((left, right) => left.offset - right.offset);
}

function sliceWidth(buckets) {
  if (buckets.length < 2) return null;
  const deltas = [];
  for (let index = 1; index < buckets.length; index += 1) {
    const delta = buckets[index].offset - buckets[index - 1].offset;
    if (delta > 0.0005) deltas.push(delta);
  }
  if (!deltas.length) return null;
  const width = Math.min(...deltas);
  const aligned = deltas.every((delta) => {
    const steps = Math.round(delta / width);
    return steps >= 1 && Math.abs(delta - steps * width) <= Math.max(0.02, width * 0.08);
  });
  return aligned && width > 0 ? width : null;
}

function formatOffset(seconds) {
  if (!Number.isFinite(seconds)) return t("common.notObserved");
  if (Math.abs(seconds) >= 60) {
    return t("charts.minutes", { minutes: Math.floor(seconds / 60), seconds: Math.round(seconds % 60) });
  }
  const digits = Math.abs(seconds) >= 10 ? 0 : 1;
  return t("charts.seconds", { value: seconds.toFixed(digits) });
}

function chartPointText(row, key) {
  const parts = [
    t("charts.offset", { seconds: formatOffset(row.offset) }),
    `${t("charts.packets")}: ${row.packets}`,
    `${t("charts.bytes")}: ${formatBytes(row.bytes)}`,
  ];
  if (key === "rate" && Number.isFinite(row.rate)) parts.push(`${t("charts.rate")}: ${row.rate.toFixed(2)}`);
  return parts.join("\n");
}

function columnChart(rows, key, series) {
  if (!rows.length) return emptyBlock(t("empty.noPackets"), t("empty.noPacketsHint"));
  const width = 640;
  const height = 220;
  const padL = 56;
  const padR = 12;
  const padT = 12;
  const padB = 28;
  const max = Math.max(...rows.map((row) => Number(row[key]) || 0), 1);
  const plotW = width - padL - padR;
  const plotH = height - padT - padB;
  const gap = rows.length > 18 ? 2 : 6;
  const barW = Math.max(2, (plotW - gap * Math.max(rows.length - 1, 0)) / rows.length);
  const grids = [0, 0.5, 1].map((ratio) => {
    const y = padT + plotH - ratio * plotH;
    const value = ratio * max;
    const label = key === "bytes" ? formatBytes(value) : key === "rate" ? value.toFixed(1) : String(Math.round(value));
    return `<line class="grid" x1="${padL}" y1="${y.toFixed(1)}" x2="${width - padR}" y2="${y.toFixed(1)}"></line><text class="axis" x="${padL - 6}" y="${(y + 4).toFixed(1)}" text-anchor="end">${esc(label)}</text>`;
  }).join("");
  const bars = rows.map((row, index) => {
    const value = Number(row[key]) || 0;
    const barHeight = value > 0 ? Math.max(2, (value / max) * plotH) : 0;
    const x = padL + index * (barW + gap);
    const y = padT + plotH - barHeight;
    return `<rect class="bar ${esc(series)}" x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW.toFixed(1)}" height="${barHeight.toFixed(1)}" rx="2" tabindex="0" data-chart-tip="${esc(chartPointText(row, key))}"></rect>`;
  }).join("");
  const axis = `<text class="axis" x="${padL}" y="${height - 8}">${esc(formatOffset(rows[0].offset))}</text><text class="axis" x="${width - padR}" y="${height - 8}" text-anchor="end">${esc(formatOffset(rows[rows.length - 1].offset))}</text>`;
  const legend = key === "bytes" ? "bytes" : key === "rate" ? "rate" : "packets";
  return `<svg class="chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="${esc(t(`charts.${legend}`))}">${grids}${bars}${axis}</svg><p class="chart-legend"><span><i class="${esc(series)}"></i>${esc(t(`charts.${legend}`))}</span></p>`;
}

function pcapCharts(buckets, protocols) {
  const rows = orderedBuckets(buckets);
  const width = sliceWidth(rows);
  const rated = width == null ? null : rows.map((row) => ({ ...row, rate: row.packets / width }));
  return `<div class="chart-grid">
    ${chartCard(t("charts.trafficTitle"), t("charts.trafficHint"), columnChart(rows, "packets", "packets"), "packet")}
    ${chartCard(t("charts.rateTitle"), t("charts.rateHint"), rated ? columnChart(rated, "rate", "rate") : emptyBlock(t("charts.rateUnavailable"), t("charts.rateUnavailableHint")))}
    ${chartCard(t("charts.protocolTitle"), t("charts.protocolHint"), protocolBars(protocols))}
    ${chartCard(t("charts.bytesTitle"), t("charts.bytesHint"), columnChart(rows, "bytes", "bytes"))}
  </div>`;
}

function chartCard(title, hint, body, concept) {
  return `<article class="panel chart-card"><h3 class="term-line"><span>${esc(title)}</span>${infoTip(concept)}</h3><p class="chart-note">${esc(hint)}</p>${body}</article>`;
}

function sparkline(buckets) {
  if (!buckets || buckets.length < 2) return "";
  const values = buckets.map((bucket) => Number(bucket.packets) || 0);
  const max = Math.max(...values, 1);
  const points = values.map((value, index) => {
    const x = (index / (values.length - 1)) * 120;
    const y = 32 - (value / max) * 28;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  return `<svg class="spark" viewBox="0 0 120 36" aria-hidden="true"><polyline points="${points}"></polyline></svg>`;
}

function severityMini(severity) {
  const entries = ["critical", "high", "medium", "low", "info"].filter((name) => severity && severity[name]);
  if (!entries.length) return "";
  const total = entries.reduce((sum, name) => sum + severity[name], 0);
  return `<div class="sev-mini">${entries.map((name) => `<i class="${name}" style="flex:${severity[name] / total}"></i>`).join("")}</div>`;
}

function chartControls(protocols) {
  const modes = [["packets", t("overview.chartPackets")], ["bytes", t("overview.chartBytes")]];
  Object.keys(protocols || {}).forEach((name) => {
    if (!modes.some((mode) => mode[0] === name)) modes.push([name, name]);
  });
  return `<div class="segment">${modes.map(([id, label]) => `<button type="button" data-chart="${esc(id)}" aria-pressed="${state.chartMode === id ? "true" : "false"}">${esc(label)}</button>`).join("")}</div>`;
}

function trafficVisual(buckets, protocols, mode) {
  if (mode !== "packets" && mode !== "bytes") return protocolBars(protocols, mode);
  const rows = orderedBuckets(buckets);
  return columnChart(rows, mode === "bytes" ? "bytes" : "packets", mode === "bytes" ? "bytes" : "packets");
}

function protocolBars(protocols, highlight) {
  const entries = Object.entries(protocols || {});
  if (!entries.length) return emptyBlock(t("empty.noProtocols"), t("empty.noProtocolsHint"));
  const max = Math.max(...entries.map(([, count]) => Number(count) || 0), 1);
  return `<div class="proto-list">${entries.map(([name, count]) => {
    const kind = conceptForProtocol(name) || "other";
    const tip = `${t("charts.protocol")}: ${name}\n${t("charts.count")}: ${count}`;
    return `<div class="proto-row ${name === highlight ? "on" : ""}" tabindex="0" data-chart-tip="${esc(tip)}">
      <span class="term-line"><i class="swatch ${esc(kind)}"></i>${esc(name)}${infoTip(conceptForProtocol(name))}</span>
      <i class="track"><b class="${esc(kind)}" style="width:${Math.round((Number(count) / max) * 100)}%"></b></i>
      <strong>${esc(count)}</strong>
    </div>`;
  }).join("")}</div><p class="quiet">${esc(t("overview.protocolNote"))}</p>`;
}

function topologyMarkup(topology, alerts) {
  const nodes = topology && topology.nodes ? topology.nodes : [];
  if (!nodes.length) {
    return `<div class="map-wrap"><div class="radar"></div><div class="map-empty"><div><strong>${esc(t("empty.awaiting"))}</strong><span>${esc(t("empty.awaitingHint"))}</span></div></div></div>`;
  }
  const width = 800;
  const height = 360;
  const placed = nodes.map((node, index) => {
    if (nodes.length === 1) return { ...node, x: width / 2, y: height / 2 };
    const angle = -Math.PI / 2 + (Math.PI * 2 * index) / nodes.length;
    return {
      ...node,
      x: width / 2 + Math.cos(angle) * width * 0.32,
      y: height / 2 + Math.sin(angle) * height * 0.32,
    };
  });
  const byId = Object.fromEntries(placed.map((node) => [node.id, node]));
  const animate = motionOk();
  const lines = (topology.links || []).map((link, index) => {
    const source = byId[link.source];
    const target = byId[link.target];
    if (!source || !target) return "";
    const protocol = esc(link.protocol || "");
    const dot = animate
      ? `<circle class="packet-dot" r="2.4"><animateMotion dur="6s" repeatCount="indefinite" begin="${index * 0.35}s" path="M ${source.x} ${source.y} L ${target.x} ${target.y}"></animateMotion></circle>`
      : "";
    return `<line class="link ${protocol}" x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}"><title>${esc(t("overview.link", { source: link.source, target: link.target, protocol: link.protocol || "" }))}</title></line>${dot}`;
  }).join("");
  const circles = placed.map((node) => {
    const level = hostSeverity(node.ip, alerts) || "normal";
    const hot = state.highlightIp && state.highlightIp === node.ip ? " hot" : "";
    return `<g class="node ${esc(level)}${hot}" data-host-ip="${esc(node.ip)}" role="button" tabindex="0">
      <circle cx="${node.x}" cy="${node.y}" r="${level === "normal" ? 8 : 10}"></circle>
      <text x="${node.x + 14}" y="${node.y + 4}">${esc(node.ip)}</text>
    </g>`;
  }).join("");
  return `<div class="map-wrap"><div class="radar"></div><svg class="topology" viewBox="0 0 ${width} ${height}" role="img" aria-label="${esc(t("overview.topology"))}">${lines}${circles}</svg></div>
    <div class="legend"><span><i class="normal"></i>${esc(t("overview.legendObserved"))}</span><span><i class="medium"></i>${esc(t("overview.legendMedium"))}</span><span><i class="high"></i>${esc(t("overview.legendHigh"))}</span><span><i class="critical"></i>${esc(t("overview.legendCritical"))}</span></div>`;
}

function openDrawer(title, body) {
  document.getElementById("drawer-title").textContent = title;
  document.getElementById("drawer-body").innerHTML = body;
  const drawer = document.getElementById("drawer");
  drawer.hidden = false;
  document.body.classList.add("drawer-open");
  drawer.querySelector(".drawer-panel button[data-close]").focus();
}

function closeDrawer() {
  document.getElementById("drawer").hidden = true;
  document.body.classList.remove("drawer-open");
}

async function openAlert(id) {
  let alert = (state.cache.alerts || state.liveFeed || []).find((item) => String(item.id) === String(id));
  if (!alert) {
    const data = await bundle();
    alert = data && data.alerts.find((item) => String(item.id) === String(id));
  }
  if (!alert) return;
  if (!state.cache.hosts || !state.cache.timeline) await bundle();
  const mac = macFor(state.cache.hosts, alert.src_ip);
  const stamps = (state.cache.timeline || [])
    .filter((item) => String(item.alert_id) === String(alert.id) && item.occurred_at)
    .map((item) => item.occurred_at)
    .sort();
  const first = stamps[0] || alert.observed_at;
  const last = stamps.length > 1 ? stamps[stamps.length - 1] : "";
  const confidence = Number(alert.confidence);
  openDrawer(alert.name || t("alert.title"), `
    <div class="actions">${badge(alert.severity)} <span>${esc(formatConfidence(alert.confidence))}</span></div>
    <div class="facts">
      <div><span class="with-tip">${esc(t("alert.detector"))}${infoTip(conceptForDetector(alert.detector_id) || "finding")}</span><strong>${esc(alert.detector_id || t("common.notObserved"))}</strong></div>
      <div><span class="with-tip">${esc(t("alert.severity"))}${infoTip("severity")}</span><strong>${esc(alert.severity ? (t(`severity.${alert.severity}`) === `severity.${alert.severity}` ? alert.severity : t(`severity.${alert.severity}`)) : t("common.notObserved"))}</strong></div>
      <div><span class="with-tip">${esc(t("alert.confidence"))}${infoTip("confidence")}</span><strong>${Number.isFinite(confidence) ? `<span class="meter"><i style="width:${Math.round(confidence * 100)}%"></i></span>${esc(formatConfidence(confidence))}` : esc(t("common.notObserved"))}</strong></div>
      <div><span>${esc(t("alert.protocol"))}</span><strong>${esc(alert.protocol || t("common.notObserved"))}</strong></div>
      <div><span>${esc(t("alert.firstSeen"))}</span><strong>${formatTime(first)}</strong></div>
      <div><span>${esc(t("alert.lastSeen"))}</span><strong>${last ? formatTime(last) : esc(t("common.notObserved"))}</strong></div>
      <div><span>${esc(t("alert.sourceIp"))}</span><strong>${esc(alert.src_ip || t("common.notObserved"))}</strong></div>
      <div><span>${esc(t("alert.sourceMac"))}</span><strong>${esc(mac || t("common.notObserved"))}</strong></div>
      <div><span>${esc(t("alert.destIp"))}</span><strong>${esc(alert.dst_ip || t("common.notObserved"))}</strong></div>
      <div><span>${esc(t("alert.destPort"))}</span><strong>${alert.dst_port == null ? esc(t("common.notObserved")) : esc(alert.dst_port)}</strong></div>
      <div><span>${esc(t("alert.status"))}</span><strong>${esc(t(`alert.statuses.${alert.status || "open"}`))}</strong></div>
    </div>
    <h2>${esc(t("learn.what"))}</h2>
    <p>${esc(lesson(alert.detector_id, "what"))}</p>
    <h2>${esc(t("learn.why"))}</h2>
    <p>${esc(lesson(alert.detector_id, "why"))}</p>
    <h2>${esc(t("learn.observed"))}</h2>
    <p>${esc(alert.evidence || t("alert.noEvidence"))}</p>
    <h2>${esc(t("learn.rule"))}</h2>
    <p>${esc(alert.name || t("common.notObserved"))} (${esc(alert.detector_id || t("alert.unknownRule"))})</p>
    <h2>${esc(t("alert.evidence"))}</h2>
    <p>${esc(alert.evidence || t("alert.noEvidence"))}</p>
    <h2>${esc(t("alert.confidence"))}</h2>
    <p>${esc(t("learn.confidence"))} ${esc(formatConfidence(alert.confidence))}</p>
    <h2>${esc(t("alert.severity"))}</h2>
    <p>${esc(t("learn.severity"))} ${esc(alert.severity ? t(`severity.${alert.severity}`) : t("common.notObserved"))}</p>
    <h2>${esc(t("alert.action"))}</h2>
    <p>${esc(alert.recommended_action || t("alert.noAction"))}</p>
    <h2>${esc(t("learn.verify"))}</h2>
    <p>${esc(lesson(alert.detector_id, "verify"))}</p>
    <h2>${esc(t("alert.lifecycle"))}</h2>
    <label class="field">${esc(t("alert.status"))}
      <select id="alert-status">
        ${["open", "acknowledged", "resolved", "dismissed"].map((status) => `<option value="${status}" ${alert.status === status ? "selected" : ""}>${esc(t(`alert.statuses.${status}`))}</option>`).join("")}
      </select>
    </label>
    <label class="field">${esc(t("alert.note"))}<textarea id="alert-note" maxlength="2000">${esc(alert.note || "")}</textarea></label>
    <button class="button primary" id="alert-save" type="button">${esc(t("alert.save"))}</button>
    <p id="alert-save-message" class="quiet"></p>`);
  document.getElementById("alert-save").addEventListener("click", async () => {
    const message = document.getElementById("alert-save-message");
    try {
      const updated = await api(`/api/alerts/${encodeURIComponent(alert.id)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status: document.getElementById("alert-status").value,
          note: document.getElementById("alert-note").value,
        }),
      });
      alert.status = updated.status;
      alert.note = updated.note;
      state.cache.bundle = null;
      if (message) message.textContent = t("alert.saved");
    } catch (error) {
      if (message) message.textContent = error.message;
    }
  });
}

async function openHost(ip) {
  if (!state.sessionId) return;
  const host = await api(`/api/analyses/${encodeURIComponent(state.sessionId)}/hosts/${encodeURIComponent(ip)}`);
  const alerts = host.alerts || [];
  const domains = host.domains || [];
  const events = host.timeline || [];
  const connections = host.connections || [];
  const level = hostSeverity(ip, alerts);
  const geo = host.geoip || { status: "unavailable", country: null, message: "GeoIP unavailable" };
  const geoText = geo.status === "observed" || geo.status === "local"
    ? geo.country
    : (geo.message || t("geoip.unavailable"));
  openDrawer(host.ip, `
    <p class="quiet">${esc(roleLabel(host.role))} ${level ? `· ${esc(t(`severity.${level}`))}` : ""}</p>
    <div class="facts">
      <div><span>${esc(t("hosts.mac"))}</span><strong>${esc((host.macs || []).join(", ") || host.mac || t("common.notObserved"))}</strong></div>
      <div><span>${esc(t("hosts.packets"))}</span><strong>${esc(host.packet_count ?? t("common.notObserved"))}</strong></div>
      <div><span>${esc(t("hosts.packetsSent"))}</span><strong>${esc(host.packets_sent)}</strong></div>
      <div><span>${esc(t("hosts.packetsReceived"))}</span><strong>${esc(host.packets_received)}</strong></div>
      <div><span>${esc(t("hosts.bytesSent"))}</span><strong>${formatBytes(host.bytes_sent)}</strong></div>
      <div><span>${esc(t("hosts.bytesReceived"))}</span><strong>${formatBytes(host.bytes_received)}</strong></div>
      <div><span>${esc(t("hosts.firstSeen"))}</span><strong>${formatTime(host.first_seen)}</strong></div>
      <div><span>${esc(t("hosts.lastSeen"))}</span><strong>${formatTime(host.last_seen)}</strong></div>
      <div><span>${esc(t("geoip.label"))}</span><strong>${esc(geoText || t("geoip.unavailable"))}</strong></div>
    </div>
    <h2>${esc(t("hosts.ports"))}</h2>
    ${(host.ports || []).length ? `<p>${host.ports.map((port) => esc(port)).join(", ")}</p>` : emptyBlock(t("empty.noPorts"), t("empty.noPortsHint"))}
    <h2>${esc(t("hosts.protocolsTitle"))}</h2>
    <p>${(host.protocols || []).length ? esc(host.protocols.join(", ")) : esc(t("common.notObserved"))}</p>
    <h2>${esc(t("hosts.domains"))}</h2>
    ${domains.length ? `<ul>${domains.map((item) => `<li>${esc(item)}</li>`).join("")}</ul>` : `<p>${esc(t("empty.noDomains"))}</p>`}
    <h2>${esc(t("hosts.connectionsTitle"))}</h2>
    ${connections.length ? tableHtml([t("hosts.source"), t("hosts.destination"), t("hosts.protocol"), t("hosts.packets"), t("hosts.bytes")], connections.slice(0, 12).map((flow) => [endpointText(flow.src_ip, flow.src_port), endpointText(flow.dst_ip, flow.dst_port), flow.protocol, flow.packet_count, formatBytes(flow.byte_count)])) : emptyBlock(t("empty.noConnections"), t("empty.noHostFlows"))}
    <h2>${esc(t("hosts.alertsTitle"))}</h2>
    ${alerts.length ? `<div class="stack">${alerts.map((item) => `<button class="button" type="button" data-alert-id="${item.id}">${badge(item.severity)} ${esc(item.name)}</button>`).join("")}</div>` : emptyBlock(t("empty.noHostEvents"), t("empty.noHostFindings"))}
    <h2>${esc(t("hosts.timelineTitle"))}</h2>
    ${events.length ? `<ol class="timeline">${events.map((item) => `<li class="${esc(item.severity || "")}"><div class="meta">${formatTime(item.occurred_at)} · ${esc(eventLabel(item.event_type))}</div><div>${esc(knownPhrase(item.summary))}</div></li>`).join("")}</ol>` : `<p>${esc(t("empty.noHostTimeline"))}</p>`}`);
}

function endpointText(ip, port) {
  if (!ip) return t("common.notObserved");
  return port == null ? ip : `${ip}:${port}`;
}

function tableHtml(headers, rows) {
  return `<div class="table-wrap"><table><thead><tr>${headers.map((header) => `<th>${esc(header)}</th>`).join("")}</tr></thead><tbody>${rows.map((row) => `<tr>${row.map((cell) => `<td>${esc(cell)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}

async function renderOverview() {
  if (!state.sessionId) {
    document.getElementById("view").innerHTML = `<section class="empty-hero"><div><p class="tagline">${esc(t("brand.tagline"))}</p><h1>${esc(t("empty.noAnalysis"))}</h1><p>${esc(t("empty.upload"))}</p><ol class="pipeline"><li>${esc(t("pipeline.capture"))}</li><li>${esc(t("pipeline.analyze"))}</li><li>${esc(t("pipeline.detect"))}</li><li>${esc(t("pipeline.understand"))}</li><li>${esc(t("pipeline.respond"))}</li></ol><div class="actions"><a class="button primary" href="#pcap">${esc(t("overview.analyze"))}</a></div></div></section>`;
    return;
  }
  const [data, alertsPayload] = await Promise.all([
    api(`/api/overview?session_id=${encodeURIComponent(state.sessionId)}`),
    api(`/api/analyses/${encodeURIComponent(state.sessionId)}/alerts`),
  ]);
  state.cache.overview = data;
  state.cache.alerts = alertsPayload.items || [];
  const stats = data.stats || {};
  const protocols = data.protocols || {};
  if (!Object.prototype.hasOwnProperty.call(protocols, state.chartMode) && state.chartMode !== "packets" && state.chartMode !== "bytes") {
    state.chartMode = "packets";
  }
  const session = data.session || {};
  document.getElementById("view").innerHTML = `
    <div class="page-head"><div><p class="eyebrow">${esc(t("overview.kicker"))}</p><h1>${esc(t("overview.title"))}</h1><p class="tagline">${esc(t("brand.tagline"))}</p><p>${esc(knownPhrase(data.notice || ""))}</p>
      <ol class="pipeline"><li>${esc(t("pipeline.capture"))}</li><li>${esc(t("pipeline.analyze"))}</li><li>${esc(t("pipeline.detect"))}</li><li>${esc(t("pipeline.understand"))}</li><li>${esc(t("pipeline.respond"))}</li></ol>
    </div></div>
    ${session.warning ? `<p class="callout">${esc(knownPhrase(session.warning))}</p>` : ""}
    <section class="kpis">
      <article class="kpi"><div class="kpi-icon"><svg viewBox="0 0 24 24"><path d="M4 12h16M7 8l-3 4 3 4M17 8l3 4-3 4"></path></svg></div><span>${esc(t("overview.packets"))}</span><strong data-count="${Number(stats.packets) || 0}">0</strong><p>${esc(t("overview.packetsHint"))}</p>${sparkline(data.traffic || [])}</article>
      <article class="kpi"><div class="kpi-icon"><svg viewBox="0 0 24 24"><path d="M5 7h14M5 12h14M5 17h8"></path></svg></div><span>${esc(t("overview.connections"))}</span><strong data-count="${Number(stats.connections) || 0}">0</strong><p>${esc(t("overview.connectionsHint"))}</p></article>
      <article class="kpi"><div class="kpi-icon"><svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="6" rx="1"></rect><rect x="4" y="14" width="16" height="6" rx="1"></rect></svg></div><span>${esc(t("overview.hosts"))}</span><strong data-count="${Number(stats.hosts) || 0}">0</strong><p>${esc(t("overview.hostsHint"))}</p></article>
      <article class="kpi"><div class="kpi-icon"><svg viewBox="0 0 24 24"><path d="M6 16V10a6 6 0 1 1 12 0v6"></path></svg></div><span>${esc(t("overview.alerts"))}</span><strong data-count="${Number(stats.alerts) || 0}">0</strong><p>${esc(t("overview.alertsHint"))}</p>${severityMini(data.severity)}</article>
    </section>
    <section class="layout">
      <article class="panel">
        <div class="panel-head"><h2>${esc(t("overview.traffic"))}</h2>${chartControls(protocols)}</div>
        <div id="traffic-chart">${trafficVisual(data.traffic || [], protocols, state.chartMode)}</div>
      </article>
      <article class="panel">
        <h2 class="term-line"><span>${esc(t("overview.severity"))}</span>${infoTip("severity")}</h2>
        ${severityRows(data.severity || {})}
      </article>
    </section>
    <section class="layout">
      <article class="panel">
        <div class="panel-head"><h2>${esc(t("overview.topology"))}</h2><span class="quiet" id="map-note"></span></div>
        <div id="net-map">${topologyMarkup(data.topology || { nodes: [], links: [] }, state.cache.alerts)}</div>
      </article>
      <article class="panel">
        <h2>${esc(t("overview.events"))}</h2>
        <div id="event-list">${alertRows(state.cache.alerts)}</div>
      </article>
    </section>
    `;
  document.querySelectorAll("[data-count]").forEach((node) => countUp(node, node.dataset.count));
  const note = document.getElementById("map-note");
  const shown = (data.topology && data.topology.nodes || []).length;
  if (note && stats.hosts > shown && shown > 0) note.textContent = t("overview.mapNote", { shown, total: stats.hosts });
}

function severityRows(severity) {
  const names = ["critical", "high", "medium", "low", "info"];
  const max = Math.max(1, ...names.map((name) => Number(severity[name]) || 0));
  return `<div class="proto-list">${names.map((name) => {
    const count = Number(severity[name]) || 0;
    return `<div class="proto-row"><span>${badge(name)}</span><i class="track"><b style="width:${Math.round((count / max) * 100)}%"></b></i><strong>${count}</strong></div>`;
  }).join("")}</div>`;
}

function paginate(items, key) {
  const size = 12;
  const pages = Math.max(1, Math.ceil(items.length / size));
  const page = Math.min(state.pages[key] || 0, pages - 1);
  state.pages[key] = page;
  return { slice: items.slice(page * size, page * size + size), page, pages };
}

function pager(key, page, pages) {
  if (pages <= 1) return "";
  return `<div class="pager"><button type="button" data-page-key="${esc(key)}" data-dir="-1" ${page === 0 ? "disabled" : ""}>${esc(t("common.previous"))}</button><span>${esc(t("common.pageOf", { page: page + 1, pages }))}</span><button type="button" data-page-key="${esc(key)}" data-dir="1" ${page === pages - 1 ? "disabled" : ""}>${esc(t("common.next"))}</button></div>`;
}
function alertRows(items) {
  const query = state.filters.alerts;
  const filtered = sortRows(items.filter((alert) => matches(query, [alert.name, alert.detector_id, alert.src_ip, alert.dst_ip, alert.protocol, alert.evidence, alert.severity])), "alerts");
  if (!items.length) return emptyBlock(t("empty.noEvents"), t("empty.noFindings"));
  if (!filtered.length) return emptyBlock(t("empty.noMatchAlerts"), t("empty.noMatchAlertsHint"));
  const page = paginate(filtered, "alerts");
  const rows = page.slice.map((alert) => `
    <tr class="${esc(alert.severity || "")}" data-alert-id="${alert.id}" tabindex="0">
      <td>${badge(alert.severity)}</td>
      <td>${esc(formatConfidence(alert.confidence))}</td>
      <td>${esc(alert.name)}<div class="meta">${esc(alert.detector_id)}</div></td>
      <td>${esc(endpointText(alert.src_ip, alert.src_port))}</td>
      <td>${esc(endpointText(alert.dst_ip, alert.dst_port))}</td>
      <td>${esc(alert.protocol || t("common.notObserved"))}</td>
      <td>${formatTime(alert.observed_at)}</td>
    </tr>`).join("");
  return `<div class="table-wrap"><table><thead><tr>
    ${header("alerts", "severity", t("alerts.severity"), "severity")}${header("alerts", "confidence", t("alerts.confidence"), "confidence")}${header("alerts", "name", t("alerts.detector"), "finding")}${header("alerts", "src_ip", t("alerts.source"))}${header("alerts", "dst_ip", t("alerts.destination"))}${header("alerts", "protocol", t("alerts.protocol"))}${header("alerts", "observed_at", t("alerts.time"))}
  </tr></thead><tbody>${rows}</tbody></table></div>${pager("alerts", page.page, page.pages)}`;
}

function header(table, key, label, concept) {
  return `<th data-sort="${esc(key)}" data-table="${esc(table)}"><span class="th-label">${esc(label)}${infoTip(concept)}</span></th>`;
}

async function renderAlerts() {
  if (!state.sessionId) {
    document.getElementById("view").innerHTML = page(t("alerts.title"), t("alerts.lead"), emptyBlock(t("empty.noAnalysis"), t("empty.upload")), "alert");
    return;
  }
  const data = await bundle();
  document.getElementById("view").innerHTML = page(t("alerts.title"), t("alerts.lead"), `
    <div class="search"><input id="alert-search" type="search" placeholder="${esc(t("alerts.search"))}" value="${esc(state.filters.alerts)}"></div>
    <div id="alert-table">${alertRows(data.alerts)}</div>`, "alert");
  document.getElementById("alert-search").addEventListener("input", (event) => {
    state.filters.alerts = event.target.value;
    state.pages.alerts = 0;
    document.getElementById("alert-table").innerHTML = alertRows(state.cache.alerts || []);
  });
}

function page(title, detail, body, concept) {
  return `<div class="page-head"><div><h1 class="term-line"><span>${esc(title)}</span>${infoTip(concept)}</h1><p>${esc(detail)}</p></div></div><section class="panel">${body}</section>`;
}

async function renderHosts() {
  if (!state.sessionId) {
    document.getElementById("view").innerHTML = page(t("hosts.title"), t("hosts.lead"), emptyBlock(t("empty.noAnalysis"), t("empty.upload")), "host");
    return;
  }
  const data = await bundle();
  document.getElementById("view").innerHTML = page(t("hosts.title"), t("hosts.lead"), `
    <div class="search"><input id="host-search" type="search" placeholder="${esc(t("hosts.search"))}" value="${esc(state.filters.hosts)}"></div>
    <div id="host-table"></div>`, "host");
  paintHosts(data.hosts);
  document.getElementById("host-search").addEventListener("input", (event) => {
    state.filters.hosts = event.target.value;
    state.pages.hosts = 0;
    paintHosts(state.cache.hosts || []);
  });
}

function paintHosts(hosts) {
  const node = document.getElementById("host-table");
  if (!node) return;
  const filtered = sortRows(hosts.filter((host) => matches(state.filters.hosts, [host.ip, ...(host.macs || []), host.role, ...(host.protocols || [])])), "hosts");
  if (!hosts.length) {
    node.innerHTML = emptyBlock(t("empty.noHosts"), t("empty.hostsHint"));
    return;
  }
  if (!filtered.length) {
    node.innerHTML = emptyBlock(t("empty.noMatchHosts"), t("empty.noMatchHostsHint"));
    return;
  }
  const page = paginate(filtered, "hosts");
  node.innerHTML = `<div class="table-wrap"><table><thead><tr>
    ${header("hosts", "ip", t("hosts.ip"))}${header("hosts", "macs", t("hosts.mac"))}${header("hosts", "packets", t("hosts.packets"))}${header("hosts", "bytes", t("hosts.bytes"))}${header("hosts", "protocols", t("hosts.protocols"))}${header("hosts", "connections", t("hosts.connections"))}${header("hosts", "alertCount", t("hosts.alerts"))}${header("hosts", "first_seen", t("hosts.firstSeen"))}${header("hosts", "last_seen", t("hosts.lastSeen"))}
  </tr></thead><tbody>${page.slice.map((host) => `<tr data-host-ip="${esc(host.ip)}" tabindex="0">
    <td>${esc(host.ip)}<div class="meta">${esc(roleLabel(host.role))}</div></td>
    <td>${esc((host.macs || []).join(", ") || t("common.notObserved"))}</td>
    <td>${esc(host.packets_sent)} ${esc(t("common.sent"))}<div class="meta">${esc(host.packets_received)} ${esc(t("common.received"))}</div></td>
    <td>${formatBytes(host.bytes_sent)} ${esc(t("common.sent"))}<div class="meta">${formatBytes(host.bytes_received)} ${esc(t("common.received"))}</div></td>
    <td>${esc((host.protocols || []).join(", ") || t("common.notObserved"))}</td>
    <td>${esc(host.connections)}</td>
    <td>${esc(host.alertCount)}</td>
    <td>${formatTime(host.first_seen)}</td>
    <td>${formatTime(host.last_seen)}</td>
  </tr>`).join("")}</tbody></table></div>${pager("hosts", page.page, page.pages)}`;
}

async function renderIocs() {
  if (!state.sessionId) {
    document.getElementById("view").innerHTML = page(t("iocs.title"), t("iocs.lead"), emptyBlock(t("empty.noAnalysis"), t("empty.upload")), "ioc");
    return;
  }
  const data = await bundle();
  const types = [...new Set(data.iocs.map((item) => item.indicator_type))];
  document.getElementById("view").innerHTML = page(t("iocs.title"), t("iocs.lead"), `
    <p class="quiet">${esc(t("intel.note"))} ${esc(intelText(data.threatIntel))}</p>
    <div class="filters">
      <input id="ioc-search" type="search" placeholder="${esc(t("iocs.search"))}" value="${esc(state.filters.iocs)}">
      <div class="segment" id="ioc-types">
        <button type="button" data-ioc-type="all" aria-pressed="${state.filters.iocType === "all" ? "true" : "false"}">${esc(t("common.all"))}</button>
        ${types.map((type) => `<button type="button" data-ioc-type="${esc(type)}" aria-pressed="${state.filters.iocType === type ? "true" : "false"}">${esc(typeLabel(type))}</button>`).join("")}
      </div>
    </div>
    <div id="ioc-table"></div>`, "ioc");
  paintIocs(data);
  document.getElementById("ioc-search").addEventListener("input", (event) => {
    state.filters.iocs = event.target.value;
    state.pages.iocs = 0;
    paintIocs(state.cache.bundle);
  });
}

function typeLabel(type) {
  const label = t(`iocs.types.${type}`);
  return label === `iocs.types.${type}` ? type : label;
}

function paintIocs(data) {
  const node = document.getElementById("ioc-table");
  if (!node || !data) return;
  const alerts = new Map(data.alerts.map((alert) => [String(alert.id), alert]));
  let items = data.iocs.map((item) => {
    const alert = alerts.get(String(item.alert_id));
    return { ...item, source: alert ? alert.src_ip : "", related: alert ? alert.name : "" };
  });
  if (state.filters.iocType !== "all") items = items.filter((item) => item.indicator_type === state.filters.iocType);
  items = sortRows(items.filter((item) => matches(state.filters.iocs, [item.value, item.indicator_type, item.source, item.related])), "iocs");
  if (!data.iocs.length) {
    node.innerHTML = emptyBlock(t("empty.noIoc"), t("empty.noIocHint"));
    return;
  }
  if (!items.length) {
    node.innerHTML = emptyBlock(t("empty.noMatchIocs"), t("empty.noMatchIocsHint"));
    return;
  }
  const page = paginate(items, "iocs");
  node.innerHTML = `<div class="table-wrap"><table><thead><tr>
    ${header("iocs", "value", t("iocs.value"))}${header("iocs", "indicator_type", t("iocs.type"))}${header("iocs", "observed_at", t("iocs.firstSeen"))}${header("iocs", "observed_at", t("iocs.lastSeen"))}${header("iocs", "source", t("iocs.source"))}${header("iocs", "related", t("iocs.related"))}
  </tr></thead><tbody>${page.slice.map((item) => `<tr>
    <td>${esc(item.value)} <button class="button copy" type="button" data-copy="${esc(item.value)}">${esc(t("common.copy"))}</button></td>
    <td>${esc(typeLabel(item.indicator_type))}</td>
    <td>${formatTime(item.observed_at)}</td>
    <td>${formatTime(item.observed_at)}<div class="meta">${esc(t("iocs.onlyObservation"))}</div></td>
    <td>${esc(item.source || t("common.notObserved"))}</td>
    <td>${item.alert_id ? `<button class="button" type="button" data-alert-id="${item.alert_id}">${esc(item.related || t("iocs.alert"))}</button>` : esc(t("common.notObserved"))}</td>
  </tr>`).join("")}</tbody></table></div>${pager("iocs", page.page, page.pages)}`;
}

async function renderTimeline() {
  if (!state.sessionId) {
    document.getElementById("view").innerHTML = page(t("timeline.title"), t("timeline.lead"), emptyBlock(t("empty.noAnalysis"), t("empty.upload")));
    return;
  }
  const data = await bundle();
  const types = [...new Set(data.timeline.map((item) => item.event_type).filter(Boolean))];
  const severities = [...new Set(data.timeline.map((item) => item.severity).filter(Boolean))];
  document.getElementById("view").innerHTML = page(t("timeline.title"), t("timeline.lead"), `
    <div class="filters">
      <select id="tl-type">${optionList(types, state.filters.timelineType, t("timeline.allTypes"), true)}</select>
      <select id="tl-severity">${optionList(severities, state.filters.timelineSeverity, t("timeline.allSeverities"), false)}</select>
      <input id="tl-source" placeholder="${esc(t("timeline.source"))}" value="${esc(state.filters.timelineSource)}">
      <input id="tl-dest" placeholder="${esc(t("timeline.destination"))}" value="${esc(state.filters.timelineDest)}">
      <input id="tl-protocol" placeholder="${esc(t("timeline.protocol"))}" value="${esc(state.filters.timelineProtocol)}">
    </div>
    <div id="timeline-list"></div>`);
  paintTimeline(data);
  ["tl-type", "tl-severity", "tl-source", "tl-dest", "tl-protocol"].forEach((id) => {
    document.getElementById(id).addEventListener("input", () => {
      state.filters.timelineType = document.getElementById("tl-type").value;
      state.filters.timelineSeverity = document.getElementById("tl-severity").value;
      state.filters.timelineSource = document.getElementById("tl-source").value;
      state.filters.timelineDest = document.getElementById("tl-dest").value;
      state.filters.timelineProtocol = document.getElementById("tl-protocol").value;
      paintTimeline(state.cache.bundle);
    });
  });
}

function optionList(values, selected, allLabel, translateEvents) {
  return [`<option value="all">${esc(allLabel)}</option>`].concat(values.map((value) => {
    const label = translateEvents ? eventLabel(value) : (t(`severity.${value}`) === `severity.${value}` ? value : t(`severity.${value}`));
    return `<option value="${esc(value)}" ${value === selected ? "selected" : ""}>${esc(label)}</option>`;
  })).join("");
}

function paintTimeline(data) {
  const node = document.getElementById("timeline-list");
  if (!node || !data) return;
  const alerts = new Map(data.alerts.map((alert) => [String(alert.id), alert]));
  const items = data.timeline.filter((item) => {
    if (state.filters.timelineType !== "all" && item.event_type !== state.filters.timelineType) return false;
    if (state.filters.timelineSeverity !== "all" && item.severity !== state.filters.timelineSeverity) return false;
    const alert = alerts.get(String(item.alert_id));
    if (state.filters.timelineSource && !(alert && String(alert.src_ip || "").includes(state.filters.timelineSource.trim()))) return false;
    if (state.filters.timelineDest && !(alert && String(alert.dst_ip || "").includes(state.filters.timelineDest.trim()))) return false;
    if (state.filters.timelineProtocol && !(alert && String(alert.protocol || "").toLowerCase().includes(state.filters.timelineProtocol.trim().toLowerCase()))) return false;
    return true;
  });
  if (!data.timeline.length) {
    node.innerHTML = emptyBlock(t("empty.noTimeline"), t("empty.timelineHint"));
    return;
  }
  if (!items.length) {
    node.innerHTML = emptyBlock(t("empty.noMatchTimeline"), t("empty.noMatchTimelineHint"));
    return;
  }
  node.innerHTML = `<ol class="timeline">${items.map((item) => `<li class="${esc(item.severity || "")}"><div class="meta">${formatTime(item.occurred_at)} · ${esc(eventLabel(item.event_type))}${item.severity ? ` · ${esc(t(`severity.${item.severity}`))}` : ""}</div><div>${esc(knownPhrase(item.summary))}</div></li>`).join("")}</ol>`;
}

async function renderReports() {
  if (!state.sessionId) {
    document.getElementById("view").innerHTML = page(t("reports.title"), t("reports.lead"), emptyBlock(t("empty.noAnalysis"), t("empty.upload")));
    return;
  }
  const detail = await api(`/api/analyses/${encodeURIComponent(state.sessionId)}`);
  document.getElementById("view").innerHTML = page(t("reports.title"), t("reports.lead"), `
    <h2>${esc(detail.name)}</h2>
    <div class="facts">
      <div><span>${esc(t("reports.status"))}</span><strong>${esc(statusLabel(detail.status))}</strong></div>
      <div><span>${esc(t("reports.source"))}</span><strong>${esc(detail.source_type || t("common.notObserved"))}</strong></div>
      <div><span>${esc(t("reports.packets"))}</span><strong>${esc(detail.packet_count)}</strong></div>
      <div><span>${esc(t("reports.alerts"))}</span><strong>${esc(detail.alert_count)}</strong></div>
      <div><span>${esc(t("reports.bytes"))}</span><strong>${formatBytes(detail.byte_count)}</strong></div>
      <div><span>${esc(t("reports.flows"))}</span><strong>${esc(detail.flow_count)}</strong></div>
      <div><span>${esc(t("reports.started"))}</span><strong>${formatTime(detail.started_at)}</strong></div>
      <div><span>${esc(t("reports.ended"))}</span><strong>${formatTime(detail.ended_at)}</strong></div>
    </div>
    <p>${esc(knownPhrase(detail.warning || "") || t("reports.noRaw"))}</p>
    <div class="actions">
      <a class="button" href="/api/analyses/${detail.id}/reports/json" target="_blank" rel="noopener">${esc(t("reports.viewJson"))}</a>
      <a class="button primary" href="/api/analyses/${detail.id}/reports/json" download>${esc(t("reports.downloadJson"))}</a>
      <a class="button" href="/api/analyses/${detail.id}/reports/pdf">${esc(t("reports.downloadPdf"))}</a>
    </div>`);
}

async function renderSettings() {
  const settings = state.settings || await api("/api/settings");
  state.settings = settings;
  document.getElementById("view").innerHTML = page(t("settings.title"), t("settings.lead"), `
    <h2>${esc(t("settings.language"))}</h2>
    <p>${esc(t("settings.languageHint"))}</p>
    <label class="field">${esc(t("common.language"))}
      <select id="settings-lang" data-lang>
        <option value="tr">🇹🇷 Türkçe</option>
        <option value="en">🇬🇧 English</option>
        <option value="ar">🇸🇦 العربية</option>
      </select>
    </label>
    <h2>${esc(t("settings.application"))}</h2>
    <p>${esc(knownPhrase(settings.notice || ""))}</p>
    <dl class="settings">
      <dt>${esc(t("settings.appName"))}</dt><dd>CyberTrace</dd>
      <dt>${esc(t("settings.uploadLimit"))}</dt><dd>${formatBytes(settings.max_upload_bytes)}</dd>
      <dt>${esc(t("settings.pcapCap"))}</dt><dd>${esc(settings.max_packets)}</dd>
      <dt>${esc(t("settings.liveCap"))}</dt><dd>${esc(settings.live_max_packets)}</dd>
      <dt>${esc(t("settings.defaultDuration"))}</dt><dd>${esc(settings.live_default_duration)} ${esc(t("common.seconds"))}</dd>
      <dt>${esc(t("settings.maxDuration"))}</dt><dd>${esc(settings.live_max_duration)} ${esc(t("common.seconds"))}</dd>
      <dt>${esc(t("settings.capture"))}</dt><dd>${settings.capture_available ? esc(t("settings.available")) : esc(t("settings.unavailable"))}</dd>
    </dl>
    <p class="${settings.capture_available ? "quiet" : "callout"}">${esc(knownPhrase(settings.capture_message || ""))}</p>
    <h2>${esc(t("theme.title"))}</h2>
    <label class="field">${esc(t("common.theme"))}
      <select id="settings-theme">
        <option value="dark">${esc(t("theme.dark"))}</option>
        <option value="light">${esc(t("theme.light"))}</option>
      </select>
    </label>
    <h2>${esc(t("rules.title"))}</h2>
    <p>${esc(t("rules.lead"))}</p>
    <div id="rule-list"></div>
    <h2>${esc(t("rules.custom"))}</h2>
    <form id="custom-rule" class="stack">
      <label class="field">${esc(t("rules.name"))}<input name="name" required maxlength="255"></label>
      <label class="field">${esc(t("rules.field"))}
        <select name="field">${["source_ip", "destination_ip", "destination_port", "protocol", "packet_count", "byte_count"].map((field) => `<option value="${field}">${esc(t(`rules.fields.${field}`))}</option>`).join("")}</select>
      </label>
      <label class="field">${esc(t("rules.operator"))}
        <select name="operator">${["equals", "not_equals", "greater_than", "less_than", "contains"].map((operator) => `<option value="${operator}">${esc(t(`rules.operators.${operator}`))}</option>`).join("")}</select>
      </label>
      <label class="field">${esc(t("rules.value"))}<input name="value" required maxlength="255"></label>
      <label class="field">${esc(t("rules.description"))}<input name="description" maxlength="1000"></label>
      <button class="button primary" type="submit">${esc(t("rules.create"))}</button>
      <p id="rule-message" class="quiet"></p>
    </form>
    <div id="custom-rule-list"></div>`);
  document.getElementById("settings-lang").value = language();
  document.getElementById("settings-lang").addEventListener("change", (event) => setLanguage(event.target.value));
  const themeSelect = document.getElementById("settings-theme");
  themeSelect.value = document.documentElement.dataset.theme || "dark";
  themeSelect.addEventListener("change", (event) => applyTheme(event.target.value));
  loadRules();
  document.getElementById("custom-rule").addEventListener("submit", saveCustomRule);
}

async function renderPcap() {
  document.getElementById("view").innerHTML = `
    <div class="page-head"><div><h1 class="term-line"><span>${esc(t("pcap.title"))}</span>${infoTip("pcap")}</h1><p>${esc(t("pcap.lead"))}</p></div></div>
    <section class="panel drop" id="drop">
      <h2>${esc(t("pcap.dropTitle"))}</h2>
      <p>${esc(t("pcap.dropHint"))}</p>
      <input id="pcap-file" type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap">
      <p class="file-meta" id="file-meta"></p>
      <div class="progress" id="upload-progress" hidden><b></b></div>
      <p class="message" id="upload-message"></p>
    </section>
    <div id="pcap-summary"></div>`;
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
  await paintPcapSummary();
}

async function paintPcapSummary() {
  const mount = document.getElementById("pcap-summary");
  if (!mount) return;
  if (!state.sessionId) {
    mount.innerHTML = `<section class="panel" style="margin-top:14px">${emptyBlock(t("empty.noAnalysis"), t("empty.upload"))}</section>`;
    return;
  }
  const data = await bundle();
  const protocols = data.detail.protocol_counts || {};
  mount.innerHTML = `
    <section class="summary-grid" style="margin-top:14px">
      ${summaryCard(t("pcap.packets"), data.detail.packet_count)}
      ${summaryCard(t("pcap.flows"), data.detail.flow_count)}
      ${summaryCard(t("pcap.hosts"), data.hosts.length)}
      ${summaryCard(t("pcap.protocols"), Object.keys(protocols).length)}
      ${summaryCard(t("pcap.alerts"), data.detail.alert_count)}
      ${summaryCard(t("pcap.iocs"), data.iocs.length)}
    </section>
    <div class="tabs" id="pcap-tabs">
      ${["traffic", "hosts", "connections", "alerts", "iocs", "timeline"].map((tab) => `<button type="button" data-pcap-tab="${tab}" aria-selected="${state.pcapTab === tab ? "true" : "false"}">${esc(t(`pcap.tabs.${tab}`))}</button>`).join("")}
    </div>
    <section class="panel" id="pcap-panel"></section>`;
  paintPcapTab(data);
  mount.querySelectorAll("[data-count]").forEach((node) => countUp(node, node.dataset.count));
}

function summaryCard(label, value) {
  return `<article class="summary-card"><span>${esc(label)}</span><strong data-count="${Number(value) || 0}">0</strong></article>`;
}

function paintPcapTab(data) {
  const panel = document.getElementById("pcap-panel");
  if (!panel) return;
  document.querySelectorAll("[data-pcap-tab]").forEach((button) => {
    button.setAttribute("aria-selected", button.dataset.pcapTab === state.pcapTab ? "true" : "false");
  });
  if (state.pcapTab === "traffic") {
    panel.innerHTML = pcapCharts(data.detail.traffic || [], data.detail.protocol_counts || {});
  } else if (state.pcapTab === "hosts") {
    panel.innerHTML = `<h2 class="term-line"><span>${esc(t("pcap.tabs.hosts"))}</span>${infoTip("host")}</h2><div id="host-table"></div>`;
    paintHosts(data.hosts);
  } else if (state.pcapTab === "connections") {
    const note = data.flowTruncated ? `<p class="quiet">${esc(t("pcap.showing", { shown: data.flows.length, total: data.flowTotal }))}</p>` : "";
    const heading = `<h2 class="term-line"><span>${esc(t("pcap.tabs.connections"))}</span>${infoTip("flow")}</h2>`;
    panel.innerHTML = data.flows.length ? `${heading}${note}${tableHtml([t("hosts.source"), t("hosts.destination"), t("hosts.protocol"), t("hosts.packets"), t("hosts.bytes"), t("hosts.started")], data.flows.map((flow) => [endpointText(flow.src_ip, flow.src_port), endpointText(flow.dst_ip, flow.dst_port), flow.protocol || t("common.notObserved"), flow.packet_count, formatBytes(flow.byte_count), formatTime(flow.started_at)]))}` : `${heading}${emptyBlock(t("empty.noConnections"), t("empty.noFlows"))}`;
  } else if (state.pcapTab === "alerts") {
    panel.innerHTML = `<h2 class="term-line"><span>${esc(t("pcap.tabs.alerts"))}</span>${infoTip("alert")}</h2>${alertRows(data.alerts)}`;
  } else if (state.pcapTab === "iocs") {
    panel.innerHTML = `<h2 class="term-line"><span>${esc(t("pcap.tabs.iocs"))}</span>${infoTip("ioc")}</h2><div id="ioc-table"></div>`;
    paintIocs(data);
  } else {
    panel.innerHTML = `<div id="timeline-list"></div>`;
    paintTimeline(data);
  }
  panel.querySelectorAll("[data-count]").forEach((node) => countUp(node, node.dataset.count));
}

function uploadFile(file) {
  const message = document.getElementById("upload-message");
  const meta = document.getElementById("file-meta");
  const progress = document.getElementById("upload-progress");
  if (!/\.(pcap|pcapng)$/i.test(file.name)) {
    message.textContent = t("errors.invalidFile");
    return;
  }
  meta.textContent = `${file.name} · ${formatBytes(file.size)}`;
  progress.hidden = false;
  progress.classList.remove("analyzing");
  progress.querySelector("b").style.width = "0%";
  message.textContent = t("pcap.uploading", { ratio: 0 });
  const xhr = new XMLHttpRequest();
  xhr.open("POST", "/api/analyses/pcap");
  xhr.upload.addEventListener("progress", (event) => {
    if (!event.lengthComputable) return;
    const ratio = Math.round((event.loaded / event.total) * 100);
    progress.querySelector("b").style.width = `${ratio}%`;
    message.textContent = t("pcap.uploading", { ratio });
  });
  xhr.upload.addEventListener("load", () => {
    progress.classList.add("analyzing");
    message.textContent = t("pcap.analyzing");
  });
  xhr.addEventListener("load", async () => {
    let body = {};
    try { body = JSON.parse(xhr.responseText || "{}"); } catch { body = {}; }
    if (xhr.status < 200 || xhr.status >= 300) {
      progress.hidden = true;
      message.textContent = typeof body.detail === "string" ? knownPhrase(body.detail) : t("pcap.failed");
      return;
    }
    setSession(body.id);
    state.cache = {};
    await loadSessions();
    message.textContent = t("pcap.finished", { name: body.name, alerts: body.alert_count, packets: body.packet_count });
    progress.hidden = true;
    await paintPcapSummary();
  });
  xhr.addEventListener("error", () => {
    progress.hidden = true;
    message.textContent = t("pcap.uploadFailed");
  });
  const body = new FormData();
  body.append("file", file);
  xhr.send(body);
}

function closeSocket() {
  if (state.socket) {
    const socket = state.socket;
    state.socket = null;
    socket.close();
  }
}

function setLiveFlag(running) {
  const flag = document.getElementById("live-flag");
  if (!flag) return;
  flag.classList.toggle("on", running);
  flag.querySelector("span:last-child").textContent = running ? t("status.live") : t("status.idle");
}

async function renderLive() {
  closeSocket();
  const info = await api("/api/interfaces");
  const status = await api("/api/live/status");
  const settings = state.settings || await api("/api/settings");
  state.settings = settings;
  const maxDuration = Number(settings.live_max_duration) || 300;
  const defaultDuration = Number(settings.live_default_duration) || 60;
  state.liveSeries = [];
  const options = (info.interfaces || []).map((item) => `<option value="${esc(item.name)}">${esc(item.description)}</option>`).join("");
  document.getElementById("view").innerHTML = `
    <div class="page-head">
      <div><h1>${esc(t("live.title"))}</h1><p>${esc(t("live.lead"))}</p></div>
      <div class="live-flag" id="live-flag"><span class="dot"></span><span>IDLE</span></div>
    </div>
    <section class="live-layout">
      <article class="panel">
        <h2>${esc(t("live.capture"))}</h2>
        <p class="${info.available ? "quiet" : "callout"}">${esc(knownPhrase(info.message || ""))}</p>
        <label class="field">${esc(t("live.interface"))}<select id="iface" ${info.available ? "" : "disabled"}>${options || `<option value="">${esc(t("live.noInterface"))}</option>`}</select></label>
        <label class="field">${esc(t("live.duration"))}<input id="duration" type="number" min="5" max="${maxDuration}" value="${defaultDuration}"></label>
        <div class="actions">
          <button class="button primary" id="start-live" type="button" ${info.available ? "" : "disabled"}>${esc(t("live.start"))}</button>
          <button class="button" id="stop-live" type="button">${esc(t("live.stop"))}</button>
        </div>
        <p id="live-message">${status.running ? esc(t("live.already")) : esc(t("live.stopped"))}<span class="quiet">${status.running ? "" : ` ${esc(t("live.stoppedHint"))}`}</span></p>
      </article>
      <article class="panel">
        <div class="panel-head"><h2>${esc(t("live.activity"))}</h2><span class="quiet" id="live-caption"></span></div>
        <h2>${esc(t("live.chart"))}</h2>
        <div id="live-chart">${liveChart(state.liveSeries)}</div>
        <div class="metric-grid">
          ${metric(t("live.pps"), "rate-packets")}
          ${metric(t("live.packets"), "count-packets")}
          ${metric("TCP", "proto-TCP")}
          ${metric("UDP", "proto-UDP")}
          ${metric("DNS", "proto-DNS")}
          ${metric("ARP", "proto-ARP")}
          ${metric("ICMP", "proto-ICMP")}
          ${metric(t("live.connections"), "count-flows")}
          ${metric(t("live.alerts"), "count-alerts")}
        </div>
        <div id="net-map">${topologyMarkup({ nodes: [], links: [] }, [])}</div>
        <h2>${esc(t("live.events"))}</h2>
        <div class="feed" id="live-feed">${emptyBlock(t("empty.noEvents"), t("empty.noFindings"))}</div>
      </article>
    </section>`;
  document.getElementById("start-live").addEventListener("click", startLive);
  document.getElementById("stop-live").addEventListener("click", stopLive);
  setLiveFlag(Boolean(status.running));
  if (status.running && status.session_id) {
    setSession(status.session_id);
    document.getElementById("live-caption").textContent = t("live.liveCapture");
    connectLive(status.session_id);
    refreshLiveMap(true);
  } else if (state.sessionId) {
    document.getElementById("live-caption").textContent = t("live.stored");
    await showStoredLive();
  }
  paintFeed();
}

function metric(label, id) {
  return `<article class="metric"><span>${esc(label)}</span><strong id="${id}">—</strong></article>`;
}

async function showStoredLive() {
  const detail = await api(`/api/analyses/${encodeURIComponent(state.sessionId)}`);
  setMetric("count-packets", detail.packet_count);
  setMetric("count-flows", detail.flow_count);
  setMetric("count-alerts", detail.alert_count);
  paintProtocols(detail.protocol_counts || {});
  await refreshLiveMap(true);
}

function setMetric(id, value) {
  const node = document.getElementById(id);
  if (node && value != null) node.textContent = String(value);
}

function paintProtocols(protocols) {
  ["TCP", "UDP", "DNS", "ARP", "ICMP"].forEach((name) => {
    const node = document.getElementById(`proto-${name}`);
    if (!node) return;
    node.textContent = Object.prototype.hasOwnProperty.call(protocols, name) ? String(protocols[name]) : "—";
  });
}

async function startLive() {
  const message = document.getElementById("live-message");
  message.textContent = t("live.starting");
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
    state.liveSeries = [];
    state.ppsSample = null;
    paintFeed();
    ["rate-packets", "count-packets", "count-flows", "count-alerts", "proto-TCP", "proto-UDP", "proto-DNS", "proto-ARP", "proto-ICMP"].forEach((id) => {
      const node = document.getElementById(id);
      if (node) node.textContent = "—";
    });
    const caption = document.getElementById("live-caption");
    if (caption) caption.textContent = t("live.liveCapture");
    message.textContent = knownPhrase(result.error_message || "") || t("live.running");
    setLiveFlag(true);
    connectLive(result.id);
    refreshLiveMap(true);
  } catch (error) {
    message.textContent = error.message;
  }
}

async function stopLive() {
  const message = document.getElementById("live-message");
  try {
    await api("/api/live/stop", { method: "POST" });
    message.textContent = `${t("live.stopped")} ${t("live.stoppedHint")}`;
    state.liveEnded = true;
    setLiveFlag(false);
    state.ppsSample = null;
    const rate = document.getElementById("rate-packets");
    if (rate) rate.textContent = "—";
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
  state.liveEnded = false;
  socket.addEventListener("close", () => {
    if (state.socket !== socket || state.route !== "live" || state.liveEnded) return;
    const message = document.getElementById("live-message");
    if (message) message.textContent = t("errors.websocket");
  });
  socket.addEventListener("message", (event) => {
    let payload = null;
    try { payload = JSON.parse(event.data); } catch { return; }
    if (state.route !== "live") return;
    if (payload.type === "stats") applyLiveStats(payload);
    if (payload.type === "alert" && payload.alert) {
      state.liveFeed.unshift(payload.alert);
      state.liveFeed = state.liveFeed.slice(0, 30);
      state.highlightIp = payload.alert.src_ip || payload.alert.dst_ip || "";
      paintFeed();
      refreshLiveMap(true);
    }
    if (payload.type === "status") {
      const message = document.getElementById("live-message");
      if (message && payload.detail) message.textContent = knownPhrase(payload.detail);
      const running = payload.status === "running";
      setLiveFlag(running);
      if (!running && payload.status !== "connected") {
        state.ppsSample = null;
        const rate = document.getElementById("rate-packets");
        if (rate) rate.textContent = "—";
        if (payload.status === "stopped" || payload.status === "completed" || payload.status === "failed") {
          state.liveEnded = true;
          const caption = document.getElementById("live-caption");
          if (caption) caption.textContent = t("live.stored");
          if (!payload.detail && message) message.textContent = `${t("live.stopped")} ${t("live.stoppedHint")}`;
        }
      }
    }
  });
}

function applyLiveStats(payload) {
  const packets = Number(payload.packet_count);
  if (state.ppsSample && Number.isFinite(packets)) {
    const elapsed = (Date.now() - state.ppsSample.at) / 1000;
    if (elapsed > 0) {
      const rate = (packets - state.ppsSample.count) / elapsed;
      const node = document.getElementById("rate-packets");
      if (node) node.textContent = rate < 10 ? rate.toFixed(1) : String(Math.round(rate));
    }
  }
  if (Number.isFinite(packets)) state.ppsSample = { at: Date.now(), count: packets };
  setMetric("count-packets", payload.packet_count);
  setMetric("count-flows", payload.connections);
  setMetric("count-alerts", payload.alerts);
  paintProtocols(payload.protocols || {});
  if (payload.observed_at && Number.isFinite(packets)) {
    const protocols = payload.protocols || {};
    state.liveSeries.push({
      at: payload.observed_at,
      packets,
      tcp: Number(protocols.TCP) || 0,
      udp: Number(protocols.UDP) || 0,
      dns: Number(protocols.DNS) || 0,
      arp: Number(protocols.ARP) || 0,
      icmp: Number(protocols.ICMP) || 0,
    });
    state.liveSeries = state.liveSeries.slice(-40);
    const chart = document.getElementById("live-chart");
    if (chart) chart.innerHTML = liveChart(state.liveSeries);
  }
  const caption = document.getElementById("live-caption");
  if (caption) caption.textContent = t("live.liveCapture");
  refreshLiveMap(false);
}

async function refreshLiveMap(force) {
  if (!state.sessionId || state.route !== "live") return;
  const now = Date.now();
  if (!force && now - state.mapAt < 2000) return;
  state.mapAt = now;
  try {
    const [overview, alerts] = await Promise.all([
      api(`/api/overview?session_id=${encodeURIComponent(state.sessionId)}`),
      api(`/api/analyses/${encodeURIComponent(state.sessionId)}/alerts`),
    ]);
    state.cache.alerts = alerts.items || [];
    const node = document.getElementById("net-map");
    if (node && state.route === "live") node.innerHTML = topologyMarkup(overview.topology || { nodes: [], links: [] }, state.cache.alerts);
  } catch {
    /* Keep the last map if a refresh fails while capture is stopping. */
  }
}

function paintFeed() {
  const feed = document.getElementById("live-feed");
  if (!feed) return;
  if (!state.liveFeed.length) {
    feed.innerHTML = emptyBlock(t("empty.noEvents"), t("empty.noFindings"));
    return;
  }
  feed.innerHTML = state.liveFeed.map((alert, index) => `
    <article class="${index === 0 ? "enter" : ""} ${esc(alert.severity || "")}" data-alert-id="${alert.id}" tabindex="0">
      <div class="meta">${badge(alert.severity)} ${esc(formatConfidence(alert.confidence))} · ${formatTime(alert.observed_at)}</div>
      <div>${esc(alert.name || t("alert.title"))}</div>
      <div class="meta">${esc(endpointText(alert.src_ip, alert.src_port))} → ${esc(endpointText(alert.dst_ip, alert.dst_port))} · ${esc(alert.protocol || "")}</div>
    </article>`).join("");
}

function onViewClick(event) {
  if (event.target.closest(".info-tip")) return;
  const pageButton = event.target.closest("[data-page-key]");
  if (pageButton && !pageButton.disabled) {
    const key = pageButton.dataset.pageKey;
    state.pages[key] = Math.max(0, (state.pages[key] || 0) + Number(pageButton.dataset.dir));
    if (key === "hosts") paintHosts(state.cache.hosts || []);
    if (key === "iocs") paintIocs(state.cache.bundle);
    if (key === "alerts") {
      const alertTable = document.getElementById("alert-table");
      const eventList = document.getElementById("event-list");
      if (alertTable) alertTable.innerHTML = alertRows(state.cache.alerts || []);
      if (eventList) eventList.innerHTML = alertRows(state.cache.alerts || []);
      if (state.route === "pcap" && state.pcapTab === "alerts" && state.cache.bundle) paintPcapTab(state.cache.bundle);
    }
    return;
  }
  const copy = event.target.closest("[data-copy]");
  if (copy) {
    const value = copy.dataset.copy || "";
    const done = () => { copy.textContent = t("common.copied"); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(value).then(done).catch(done);
    else done();
    return;
  }
  const chart = event.target.closest("[data-chart]");
  if (chart) {
    state.chartMode = chart.dataset.chart;
    const overview = state.cache.overview;
    const data = state.cache.bundle;
    const protocols = overview ? overview.protocols || {} : (data && data.detail.protocol_counts) || {};
    const buckets = overview ? overview.traffic || [] : (data && data.detail.traffic) || [];
    document.querySelectorAll("[data-chart]").forEach((button) => button.setAttribute("aria-pressed", button.dataset.chart === state.chartMode ? "true" : "false"));
    const mount = document.getElementById("traffic-chart");
    if (mount) mount.innerHTML = trafficVisual(buckets, protocols, state.chartMode);
    return;
  }
  const tab = event.target.closest("[data-pcap-tab]");
  if (tab && state.cache.bundle) {
    state.pcapTab = tab.dataset.pcapTab;
    paintPcapTab(state.cache.bundle);
    return;
  }
  const iocType = event.target.closest("[data-ioc-type]");
  if (iocType) {
    state.filters.iocType = iocType.dataset.iocType;
    document.querySelectorAll("[data-ioc-type]").forEach((button) => button.setAttribute("aria-pressed", button.dataset.iocType === state.filters.iocType ? "true" : "false"));
    paintIocs(state.cache.bundle);
    return;
  }
  const sort = event.target.closest("[data-sort]");
  if (sort) {
    const table = sort.dataset.table;
    const key = sort.dataset.sort;
    const current = state.sort[table];
    state.sort[table] = { key, dir: current && current.key === key ? current.dir * -1 : 1 };
    if (table === "hosts") paintHosts(state.cache.hosts || []);
    if (table === "alerts") {
      const alertTable = document.getElementById("alert-table");
      const eventList = document.getElementById("event-list");
      if (alertTable) alertTable.innerHTML = alertRows(state.cache.alerts || []);
      if (eventList) eventList.innerHTML = alertRows(state.cache.alerts || []);
      if (state.route === "pcap" && state.pcapTab === "alerts" && state.cache.bundle) paintPcapTab(state.cache.bundle);
    }
    if (table === "iocs") paintIocs(state.cache.bundle);
    return;
  }
  const alertEl = event.target.closest("[data-alert-id]");
  if (alertEl && !event.target.closest("[data-sort]")) {
    openAlert(alertEl.dataset.alertId);
    return;
  }
  const hostEl = event.target.closest("[data-host-ip]");
  if (hostEl) openHost(hostEl.dataset.hostIp);
}

function onViewKey(event) {
  if (event.key !== "Enter") return;
  const alertEl = event.target.closest("[data-alert-id]");
  if (alertEl) openAlert(alertEl.dataset.alertId);
  const hostEl = event.target.closest("[data-host-ip]");
  if (hostEl) openHost(hostEl.dataset.hostIp);
}

let renderToken = 0;

async function render() {
  const token = ++renderToken;
  closeDrawer();
  const route = routes.includes(state.route) ? state.route : "overview";
  state.route = route;
  document.querySelectorAll("#nav a[data-route]").forEach((link) => {
    if (link.dataset.route === route) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  if (route !== "live") closeSocket();
  const view = document.getElementById("view");
  view.classList.remove("is-entering");
  view.innerHTML = skeleton();
  try {
    await loadSessions();
    if (token !== renderToken) return;
    const pages = { overview: renderOverview, live: renderLive, pcap: renderPcap, alerts: renderAlerts, hosts: renderHosts, iocs: renderIocs, timeline: renderTimeline, reports: renderReports, settings: renderSettings };
    await pages[route]();
    if (token !== renderToken) return;
    view.classList.add("is-entering");
  } catch (error) {
    view.innerHTML = `<p class="callout">${esc(error.message || t("errors.backend"))}</p>`;
  }
}

function syncRoute() {
  state.route = (location.hash || "#overview").slice(1) || "overview";
  document.body.classList.remove("nav-open");
  document.getElementById("scrim").hidden = true;
  render();
}

async function refreshHealth() {
  const node = document.getElementById("health");
  try {
    const body = await api("/health");
    const ok = body.status === "ok" && body.database === "ok";
    node.className = `op ${ok ? "ok" : "bad"}`;
    node.innerHTML = `<span class="pulse"></span><span>${ok ? t("status.operational") : t("status.degraded")}</span>`;
  } catch {
    node.className = "op bad";
    node.innerHTML = `<span class="pulse"></span><span>${t("status.unavailable")}</span>`;
  }
}

document.getElementById("view").addEventListener("click", onViewClick);
document.getElementById("view").addEventListener("keydown", onViewKey);
document.getElementById("drawer").addEventListener("click", (event) => {
  if (event.target.closest("[data-close]")) closeDrawer();
  const alertEl = event.target.closest("[data-alert-id]");
  if (alertEl) openAlert(alertEl.dataset.alertId);
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeDrawer();
});
document.getElementById("session-select").addEventListener("change", (event) => {
  setSession(event.target.value);
  render();
});
document.getElementById("nav-toggle").addEventListener("click", () => {
  document.body.classList.toggle("nav-collapsed");
  localStorage.setItem("cybertrace-nav", document.body.classList.contains("nav-collapsed") ? "1" : "0");
});
document.getElementById("menu-button").addEventListener("click", () => {
  document.body.classList.add("nav-open");
  document.getElementById("scrim").hidden = false;
});
document.getElementById("scrim").addEventListener("click", () => {
  document.body.classList.remove("nav-open");
  document.getElementById("scrim").hidden = true;
});
document.getElementById("lang-select").addEventListener("change", (event) => {
  setLanguage(event.target.value);
});
document.getElementById("theme-select").addEventListener("change", (event) => {
  applyTheme(event.target.value);
});
onLanguage(() => {
  refreshHealth();
  render();
});
if (localStorage.getItem("cybertrace-nav") === "1") document.body.classList.add("nav-collapsed");
window.addEventListener("hashchange", syncRoute);

function lesson(detector, part) {
  const key = `lessons.${detector}.${part}`;
  const value = t(key);
  return value === key ? t(`lessons.generic.${part}`) : value;
}

function intelText(info) {
  if (info && info.status === "configured") return t("intel.configured");
  return t("intel.unavailable");
}

function liveChart(series) {
  if (!series || series.length < 2) return emptyBlock(t("live.chartEmpty"), t("live.chartEmptyHint"));
  const width = 640;
  const height = 160;
  const max = Math.max(1, ...series.map((point) => Number(point.packets) || 0));
  const step = (width - 24) / (series.length - 1);
  const line = (key) => series.map((point, index) => {
    const x = 12 + index * step;
    const y = height - 16 - ((Number(point[key]) || 0) / max) * (height - 32);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  const latest = series[series.length - 1];
  return `<svg class="live-chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="${esc(t("live.chart"))}"><polyline points="${line("packets")}" class="packets"></polyline><polyline points="${line("tcp")}" class="tcp"></polyline><polyline points="${line("udp")}" class="udp"></polyline><polyline points="${line("dns")}" class="dns"></polyline></svg><p class="quiet">${esc(latest.at)} · TCP ${esc(latest.tcp)} · UDP ${esc(latest.udp)} · DNS ${esc(latest.dns)} · ARP ${esc(latest.arp)} · ICMP ${esc(latest.icmp)}</p>`;
}

function applyTheme(theme) {
  const next = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  localStorage.setItem("cybertrace-theme", next);
  document.querySelectorAll("#theme-select, #settings-theme").forEach((node) => {
    node.value = next;
  });
}

async function loadRules() {
  const list = document.getElementById("rule-list");
  const custom = document.getElementById("custom-rule-list");
  if (!list) return;
  try {
    const [rules, customRules, context] = await Promise.all([
      api("/api/rules"),
      api("/api/custom-rules"),
      api("/api/context/status"),
    ]);
    const geo = context.geoip && context.geoip.status === "observed" ? t("geoip.ready") : t("geoip.unavailable");
    const intel = context.threat_intel && context.threat_intel.status === "configured" ? t("intel.configured") : t("intel.unavailable");
    const email = context.email && context.email.enabled ? t("email.enabled") : t("email.disabled");
    list.innerHTML = `<p class="quiet">${esc(t("geoip.label"))}: ${esc(geo)} · ${esc(t("intel.note"))} ${esc(intel)} · ${esc(t("email.label"))} ${esc(email)}</p>` + (rules.items || []).map((rule) => `
      <label class="rule-row"><input type="checkbox" data-rule-id="${esc(rule.rule_id)}" ${rule.enabled ? "checked" : ""}><span><strong>${esc(rule.rule_id)}</strong><br>${esc(rule.description || "")}</span></label>`).join("");
    list.querySelectorAll("[data-rule-id]").forEach((input) => {
      input.addEventListener("change", async () => {
        await api(`/api/rules/${encodeURIComponent(input.dataset.ruleId)}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: input.checked }),
        });
      });
    });
    custom.innerHTML = (customRules.items || []).length
      ? customRules.items.map((rule) => `<p>${esc(rule.name)} · ${esc(rule.field)} ${esc(rule.operator)} ${esc(rule.value)}</p>`).join("")
      : `<p class="quiet">${esc(t("rules.none"))}</p>`;
  } catch (error) {
    list.innerHTML = `<p class="callout">${esc(error.message)}</p>`;
  }
}

async function saveCustomRule(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const message = document.getElementById("rule-message");
  const body = Object.fromEntries(new FormData(form).entries());
  try {
    await api("/api/custom-rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    form.reset();
    if (message) message.textContent = t("rules.saved");
    await loadRules();
  } catch (error) {
    if (message) message.textContent = error.message;
  }
}

function showFloating(id, text, anchor) {
  const tip = document.getElementById(id);
  if (!tip || !anchor) return;
  tip.textContent = text || "";
  tip.hidden = false;
  const bounds = anchor.getBoundingClientRect();
  const box = tip.getBoundingClientRect();
  const rtl = document.documentElement.dir === "rtl";
  let left = rtl ? bounds.right - box.width : bounds.left;
  left = Math.max(8, Math.min(left, window.innerWidth - box.width - 8));
  let top = bounds.bottom + 8;
  if (top + box.height > window.innerHeight - 8) top = Math.max(8, bounds.top - box.height - 8);
  tip.style.left = `${left}px`;
  tip.style.top = `${top}px`;
}

function hideFloating(id) {
  const tip = document.getElementById(id);
  if (tip) tip.hidden = true;
}

const tipHover = window.matchMedia("(hover: hover) and (pointer: fine)");
document.addEventListener("pointerover", (event) => {
  if (!tipHover.matches) return;
  const info = event.target.closest && event.target.closest(".info-tip");
  if (info) {
    showFloating("term-tip", info.dataset.tip || "", info);
    return;
  }
  const point = event.target.closest && event.target.closest("[data-chart-tip]");
  if (point) showFloating("chart-tip", point.dataset.chartTip || "", point);
});
document.addEventListener("pointerout", (event) => {
  if (event.target.closest && event.target.closest(".info-tip")) hideFloating("term-tip");
  if (event.target.closest && event.target.closest("[data-chart-tip]")) hideFloating("chart-tip");
});
document.addEventListener("focusin", (event) => {
  const info = event.target.closest && event.target.closest(".info-tip");
  if (info) showFloating("term-tip", info.dataset.tip || "", info);
  const point = event.target.closest && event.target.closest("[data-chart-tip]");
  if (point) showFloating("chart-tip", point.dataset.chartTip || "", point);
});
document.addEventListener("focusout", () => {
  hideFloating("term-tip");
  hideFloating("chart-tip");
});
document.addEventListener("click", (event) => {
  const info = event.target.closest && event.target.closest(".info-tip");
  if (!info || tipHover.matches) return;
  event.preventDefault();
  const tip = document.getElementById("term-tip");
  if (tip && !tip.hidden) {
    hideFloating("term-tip");
    return;
  }
  showFloating("term-tip", info.dataset.tip || "", info);
});
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  hideFloating("term-tip");
  hideFloating("chart-tip");
});

async function boot() {
  applyTheme(localStorage.getItem("cybertrace-theme") || "dark");
  try {
    await initI18n();
  } catch {
    document.documentElement.lang = "en";
  }
  applyChrome();
  refreshHealth();
  syncRoute();
}

boot();
