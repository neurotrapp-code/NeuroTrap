/* NeuroTrap / CADN live console.
   Every value rendered here comes from the live API (/api/*) and the live
   WebSocket feed (/ws/live-feed). There is no sample/demo data in this client. */
"use strict";
const $ = (id) => document.getElementById(id);
let TOKEN = localStorage.getItem("cadn_token") || "";
let map, markers, timelineChart, ws;
const minuteBuckets = new Map();   // "HH:MM" -> count

/* ---------- auth ---------- */
$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const r = await fetch("/api/auth/login", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: $("u").value, password: $("p").value }),
  });
  if (!r.ok) { $("login-err").textContent = "Invalid credentials"; return; }
  TOKEN = (await r.json()).token;
  localStorage.setItem("cadn_token", TOKEN);
  start();
});
$("logout").addEventListener("click", () => {
  localStorage.removeItem("cadn_token"); location.reload();
});

const authHeaders = () => ({ "Authorization": "Bearer " + TOKEN });

async function api(path) {
  const r = await fetch(path, { headers: authHeaders() });
  if (r.status === 401) { localStorage.removeItem("cadn_token"); location.reload(); }
  return r.json();
}

/* ---------- bootstrap ---------- */
async function start() {
  $("login").classList.add("hidden");
  $("app").classList.remove("hidden");
  initMap();
  initTimeline();
  await Promise.all([loadStats(), loadEvents(), loadResponses()]);
  connectFeed();
  setInterval(loadStats, 5000);         // stats refresh
  setInterval(loadResponses, 7000);
}

if (TOKEN) start();   // resume session

/* ---------- map ---------- */
function initMap() {
  map = L.map("map", { worldCopyJump: true }).setView([20, 0], 2);
  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    attribution: "© OpenStreetMap, © CARTO", subdomains: "abcd", maxZoom: 19,
  }).addTo(map);
  markers = L.layerGroup().addTo(map);
}
let geoSeen = 0;
function plotGeo(ev) {
  if (!ev.geo || ev.geo.lat == null) return;
  geoSeen++;
  const color = sevColor(ev.severity);
  L.circleMarker([ev.geo.lat, ev.geo.lon], {
    radius: 6, color, fillColor: color, fillOpacity: .7, weight: 1,
  }).bindPopup(`<b>${ev.src_ip}</b><br>${ev.attack_type} (${ev.severity})<br>${ev.geo.city||""} ${ev.geo.country||""}`)
    .addTo(markers);
}
function sevColor(s){return s==="high"||s==="critical"?"#ff5d5d":s==="medium"?"#ffb454":"#5aa9ff";}

/* ---------- timeline ---------- */
function initTimeline() {
  timelineChart = new Chart($("timeline"), {
    type: "line",
    data: { labels: [], datasets: [{ label: "events/min", data: [],
      borderColor: "#3ddc97", backgroundColor: "rgba(61,220,151,.15)", fill: true, tension: .3 }] },
    options: { plugins: { legend: { display: false } },
      scales: { x: { ticks: { color: "#8a97ad" } }, y: { ticks: { color: "#8a97ad" }, beginAtZero: true } } },
  });
}
function bumpTimeline(ts) {
  const d = new Date(ts || Date.now());
  const key = d.toTimeString().slice(0, 5);
  minuteBuckets.set(key, (minuteBuckets.get(key) || 0) + 1);
  const keys = [...minuteBuckets.keys()].slice(-20);
  timelineChart.data.labels = keys;
  timelineChart.data.datasets[0].data = keys.map((k) => minuteBuckets.get(k));
  timelineChart.update("none");
}

/* ---------- stats + gauge ---------- */
async function loadStats() {
  const s = await api("/api/stats");
  $("s-total").textContent = s.total_events;
  $("s-profiles").textContent = s.profiles;
  $("s-responses").textContent = s.responses;
  // peak threat = highest profile score among top sources
  let peak = 0;
  for (const t of (s.top_sources || []).slice(0, 5)) {
    const a = await api("/api/attackers/" + t.src_ip);
    if (a.profile && a.profile.threat_score > peak) peak = a.profile.threat_score;
  }
  $("s-threat").textContent = peak;
  $("gauge-fill").style.width = peak + "%";
  renderProfiles(s.top_sources || []);
}

async function renderProfiles(top) {
  const box = $("profiles"); box.innerHTML = "";
  for (const t of top.slice(0, 5)) {
    const a = await api("/api/attackers/" + t.src_ip);
    const p = a.profile || {};
    const band = bandFor(p.threat_score || 0);
    const div = document.createElement("div");
    div.className = "pcard";
    div.innerHTML = `<div><div class="ip">${t.src_ip}</div>
      <div class="meta">${p.classified_intent || "—"} · ${(p.ttps||[]).length} TTPs · ${t.count} events</div></div>
      <span class="badge b-${band}">${p.threat_score ?? 0}</span>`;
    box.appendChild(div);
  }
}
function bandFor(s){return s<40?"log":s<70?"slow_redirect":s<90?"isolate":"block";}

/* ---------- events feed ---------- */
async function loadEvents() {
  const { events } = await api("/api/events?limit=50");
  events.reverse().forEach((e) => { addEvent(e, false); });
}
function addEvent(e, flash = true) {
  const tb = $("feed");
  const tr = document.createElement("tr");
  if (flash) tr.className = "flash";
  tr.innerHTML = `<td>${(e.timestamp||"").slice(11,19)}</td><td>${e.src_ip}</td>
    <td>${e.attack_type}</td><td class="sev-${e.severity}">${e.severity}</td>
    <td>${e.detail||e.raw_payload||""}</td>`;
  tb.prepend(tr);
  while (tb.children.length > 80) tb.removeChild(tb.lastChild);
  plotGeo(e);
  bumpTimeline(e.timestamp);
}

/* ---------- responses ---------- */
async function loadResponses() {
  const { responses } = await api("/api/responses?limit=40");
  const tb = $("responses"); tb.innerHTML = "";
  responses.forEach((r) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${(r.ts||"").slice(11,19)}</td><td>${r.src_ip}</td>
      <td>${r.action}</td><td><span class="badge b-${r.band}">${r.band}</span></td>
      <td>${r.success ? "✓" : "✗"}</td>`;
    tb.appendChild(tr);
  });
}

/* ---------- live websocket ---------- */
function connectFeed() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  try {
    ws = new WebSocket(`${proto}://${location.host}/ws/live-feed?token=${TOKEN}`);
    ws.onopen = () => { $("conn").textContent = "live feed connected"; };
    ws.onmessage = (m) => {
      const msg = JSON.parse(m.data);
      if (msg.type === "event") addEvent(msg.data, true);
    };
    ws.onclose = () => { $("conn").textContent = "feed closed — polling"; pollFallback(); };
    ws.onerror = () => { try { ws.close(); } catch (e) {} };
  } catch (e) { pollFallback(); }
}
let lastPollId = 0, pollTimer;
function pollFallback() {
  if (pollTimer) return;
  pollTimer = setInterval(async () => {
    const { events } = await api("/api/events?limit=20");
    events.reverse().forEach((e) => { if (e.id > lastPollId) { lastPollId = e.id; addEvent(e, true); } });
  }, 3000);
}
