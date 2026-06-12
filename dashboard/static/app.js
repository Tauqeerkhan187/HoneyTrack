// HoneyTrack SOC Dashboard — frontend logic
// Consumes /api/summary. Counter.most_common() returns [["item", count], ...] pairs.

const REFRESH_MS = 15000;
let tacticsChart = null;
let ttpChart = null;

const COLORS = {
  accent: "#00e5a0",
  info: "#3b9dff",
  warn: "#ffb020",
  danger: "#ff4d5e",
  palette: ["#00e5a0", "#3b9dff", "#ffb020", "#ff4d5e", "#a78bfa", "#22d3ee", "#f472b6", "#84cc16", "#fb923c", "#94a3b8"],
};

function setStatus(text, cls) {
  const el = document.getElementById("status");
  el.textContent = text;
  el.className = "status" + (cls ? " " + cls : "");
}

function riskBadge(score) {
  if (score === null || score === undefined) return '<span class="risk risk-low">n/a</span>';
  let cls = "risk-low";
  if (score >= 70) cls = "risk-high";
  else if (score >= 30) cls = "risk-med";
  return `<span class="risk ${cls}">${score}</span>`;
}

async function fetchSummary() {
  const enrich = document.getElementById("enrichToggle").checked ? "1" : "0";
  setStatus("refreshing…");
  try {
    const res = await fetch(`/api/summary?enrich=${enrich}`);
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();
    render(data);
    setStatus("live", "live");
    document.getElementById("lastUpdate").textContent =
      "updated " + new Date().toLocaleTimeString();
  } catch (err) {
    console.error(err);
    setStatus("error: " + err.message, "error");
  }
}

function render(data) {
  // Stat cards
  document.getElementById("statSessions").textContent = data.total_sessions ?? 0;
  document.getElementById("statAttackers").textContent = data.unique_attackers ?? 0;
  document.getElementById("statCommands").textContent = data.total_commands ?? 0;
  document.getElementById("statTtps").textContent = (data.top_ttps || []).length;

  renderTacticsChart(data.top_tactics || []);
  renderTtpChart(data.top_ttps || []);
  renderAttackerTable(data);
  renderCommandTable(data.top_commands || []);
}

function renderTacticsChart(pairs) {
  const labels = pairs.map((p) => p[0]);
  const values = pairs.map((p) => p[1]);
  const ctx = document.getElementById("tacticsChart");

  if (tacticsChart) tacticsChart.destroy();
  tacticsChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels,
      datasets: [{ data: values, backgroundColor: COLORS.palette, borderColor: "#0a0e14", borderWidth: 2 }],
    },
    options: {
      plugins: { legend: { position: "right", labels: { color: "#8595a8", font: { size: 11 } } } },
      cutout: "62%",
    },
  });
}

function renderTtpChart(pairs) {
  const labels = pairs.map((p) => p[0]);
  const values = pairs.map((p) => p[1]);
  const ctx = document.getElementById("ttpChart");

  if (ttpChart) ttpChart.destroy();
  ttpChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{ label: "Occurrences", data: values, backgroundColor: COLORS.info, borderRadius: 4 }],
    },
    options: {
      indexAxis: "y",
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#8595a8" }, grid: { color: "#1a2433" } },
        y: { ticks: { color: "#8595a8", font: { size: 10 } }, grid: { display: false } },
      },
    },
  });
}

function renderAttackerTable(data) {
  const tbody = document.getElementById("attackerTable");
  const enriched = data.enriched_ips || [];

  // Prefer enriched rows when available; otherwise fall back to top_ips pairs.
  let rows;
  if (enriched.length) {
    rows = enriched.map((e) => {
      const abuse = e.abuseipdb || {};
      return `<tr>
        <td class="mono">${e.ip}</td>
        <td>${e.session_count ?? "—"}</td>
        <td>${riskBadge(e.risk_score)}</td>
        <td>${abuse.country_code || "—"}</td>
        <td>${abuse.isp || "—"}</td>
      </tr>`;
    });
  } else {
    rows = (data.top_ips || []).map(
      (p) => `<tr>
        <td class="mono">${p[0]}</td>
        <td>${p[1]}</td>
        <td>${riskBadge(null)}</td>
        <td>—</td><td>—</td>
      </tr>`
    );
  }

  tbody.innerHTML = rows.length
    ? rows.join("")
    : '<tr><td colspan="5" class="empty">No data yet — run some attacks from Kali.</td></tr>';
}

function renderCommandTable(pairs) {
  const tbody = document.getElementById("commandTable");
  const rows = pairs.map(
    (p) => `<tr><td class="mono">${escapeHtml(p[0])}</td><td>${p[1]}</td></tr>`
  );
  tbody.innerHTML = rows.length
    ? rows.join("")
    : '<tr><td colspan="2" class="empty">No data yet.</td></tr>';
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

document.getElementById("refreshBtn").addEventListener("click", fetchSummary);
document.getElementById("enrichToggle").addEventListener("change", fetchSummary);

fetchSummary();
setInterval(fetchSummary, REFRESH_MS);