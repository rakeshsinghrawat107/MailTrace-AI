/**
 * MailTrace AI - Modern Enterprise SOC Forensics Controller
 * Implements accessible keyboard interactions, tab state synchronization,
 * dynamic 32D radar rendering, interactive MTA hop tracing, and Section 63 BSA validation.
 */

let currentCase = null;
let leafletMap = null;
let mapMarkers = [];
let mapPolyline = null;
let radarChart = null;

// Initialize on DOM ready
document.addEventListener("DOMContentLoaded", () => {
  if (window.lucide) {
    window.lucide.createIcons();
  }

  initLeafletMap();
  initRadarChart();
  setupEventListeners();

  // Load default forensic scenario (Spear Phishing)
  loadSampleCase("spear_phishing");
});

function initLeafletMap() {
  const mapElem = document.getElementById("leaflet-map");
  if (!mapElem) return;

  leafletMap = L.map("leaflet-map", {
    center: [25.0, 30.0],
    zoom: 2,
    zoomControl: true,
    attributionControl: false
  });

  // High-contrast CartoDB Dark Matter tiles
  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    subdomains: "abcd",
    maxZoom: 19
  }).addTo(leafletMap);
}

function initRadarChart() {
  const ctx = document.getElementById("radarChart");
  if (!ctx) return;

  radarChart = new Chart(ctx, {
    type: "radar",
    data: {
      labels: [
        "Protocol Auth",
        "Header Alignment",
        "De-Obfuscation",
        "Urgency NLP",
        "Quishing Evasion",
        "Network Provenance"
      ],
      datasets: [{
        label: "Risk Exposure Index",
        data: [0, 0, 0, 0, 0, 0],
        backgroundColor: "rgba(6, 182, 212, 0.22)",
        borderColor: "rgba(6, 182, 212, 0.9)",
        pointBackgroundColor: "#38bdf8",
        pointBorderColor: "#ffffff",
        pointHoverBackgroundColor: "#ffffff",
        pointHoverBorderColor: "#38bdf8",
        pointRadius: 3,
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          angleLines: { color: "rgba(255, 255, 255, 0.12)" },
          grid: { color: "rgba(255, 255, 255, 0.08)" },
          pointLabels: {
            color: "#94a3b8",
            font: { family: '"Inter", sans-serif', size: 10, weight: 600 }
          },
          ticks: {
            display: false,
            max: 100,
            min: 0,
            stepSize: 20
          },
          suggestedMin: 0,
          suggestedMax: 100
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

function setupEventListeners() {
  // Sample case selection buttons
  document.querySelectorAll(".sample-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const sampleKey = btn.getAttribute("data-sample");
      loadSampleCase(sampleKey);
    });
  });

  // Accessible Pill Tab Navigation
  document.querySelectorAll(".tab-nav-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-target");

      document.querySelectorAll(".tab-nav-btn").forEach(b => {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
      });
      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");

      document.querySelectorAll(".tab-panel").forEach(panel => {
        panel.classList.add("hidden");
      });
      const activePanel = document.getElementById(targetId);
      if (activePanel) {
        activePanel.classList.remove("hidden");
        if (targetId === "tab-trace-map" && leafletMap) {
          setTimeout(() => leafletMap.invalidateSize(), 150);
        }
      }
    });
  });

  // Keyboard navigation & accessibility shortcuts
  document.addEventListener("keydown", (e) => {
    // Close modal on Escape
    if (e.key === "Escape") {
      const certModal = document.getElementById("cert-modal");
      if (certModal && !certModal.classList.contains("hidden")) {
        certModal.classList.add("hidden");
      }
    }

    // Quick scenario hotkeys 1-4 when not typing in form inputs
    if (!["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) {
      if (e.key === "1") loadSampleCase("spear_phishing");
      else if (e.key === "2") loadSampleCase("bec_wire_fraud");
      else if (e.key === "3") loadSampleCase("quishing_invoice");
      else if (e.key === "4") loadSampleCase("legitimate_gov");
    }
  });

  // File upload input
  const fileInput = document.getElementById("eml-file-input");
  if (fileInput) {
    fileInput.addEventListener("change", (e) => {
      if (e.target.files && e.target.files[0]) {
        uploadEmlFile(e.target.files[0]);
      }
    });
  }

  // Section 63 BSA Modal listeners
  const btnOpenCert = document.getElementById("btn-open-certificate");
  const certModal = document.getElementById("cert-modal");
  const btnCloseModal = document.getElementById("btn-close-modal");
  const btnCopyCert = document.getElementById("btn-copy-cert");
  const btnPrintCert = document.getElementById("btn-print-cert");

  if (btnOpenCert && certModal) {
    btnOpenCert.addEventListener("click", openCertificateModal);
  }
  if (btnCloseModal && certModal) {
    btnCloseModal.addEventListener("click", () => certModal.classList.add("hidden"));
  }
  if (certModal) {
    // Close when clicking overlay backdrop
    certModal.addEventListener("click", (e) => {
      if (e.target === certModal) {
        certModal.classList.add("hidden");
      }
    });
  }

  if (btnCopyCert) {
    btnCopyCert.addEventListener("click", () => {
      const text = document.getElementById("cert-raw-text").innerText;
      navigator.clipboard.writeText(text).then(() => {
        const originalText = btnCopyCert.innerText;
        btnCopyCert.innerText = "Copied!";
        btnCopyCert.classList.add("text-emerald-300");
        setTimeout(() => {
          btnCopyCert.innerText = originalText;
          btnCopyCert.classList.remove("text-emerald-300");
        }, 2000);
      });
    });
  }

  if (btnPrintCert) {
    btnPrintCert.addEventListener("click", () => window.print());
  }

  // Copy SHA-256 Hash Button
  const btnCopyHash = document.getElementById("btn-copy-hash");
  if (btnCopyHash) {
    btnCopyHash.addEventListener("click", () => {
      const hashText = document.getElementById("meta-sha256").innerText;
      if (hashText && hashText !== "Calculating...") {
        navigator.clipboard.writeText(hashText).then(() => {
          btnCopyHash.innerHTML = `<i data-lucide="check" class="w-3.5 h-3.5 text-emerald-400"></i>`;
          if (window.lucide) window.lucide.createIcons();
          setTimeout(() => {
            btnCopyHash.innerHTML = `<i data-lucide="copy" class="w-3.5 h-3.5"></i>`;
            if (window.lucide) window.lucide.createIcons();
          }, 2000);
        });
      }
    });
  }

  // Header quick export actions
  const btnHeaderPdf = document.getElementById("btn-header-pdf");
  const btnHeaderJson = document.getElementById("btn-header-json");
  if (btnHeaderPdf) {
    btnHeaderPdf.addEventListener("click", () => window.print());
  }
  if (btnHeaderJson) {
    btnHeaderJson.addEventListener("click", () => {
      if (currentCase) {
        window.open(`/api/evidence/case/${currentCase.case_id}`, "_blank");
      }
    });
  }

  // IoC Export buttons
  const btnCsv = document.getElementById("btn-export-csv");
  const btnJson = document.getElementById("btn-export-json");
  if (btnCsv) {
    btnCsv.addEventListener("click", () => exportIoCs("csv"));
  }
  if (btnJson) {
    btnJson.addEventListener("click", () => exportIoCs("json"));
  }
}

async function loadSampleCase(sampleKey) {
  try {
    const res = await fetch(`/api/samples/${sampleKey}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderCaseData(data);
  } catch (err) {
    console.error("Error loading sample case:", err);
  }
}

async function uploadEmlFile(file) {
  try {
    const formData = new FormData();
    formData.append("file", file);
    const res = await fetch("/api/analyze/upload", {
      method: "POST",
      body: formData
    });
    if (!res.ok) throw new Error(`Upload failed HTTP ${res.status}`);
    const data = await res.json();
    renderCaseData(data);
  } catch (err) {
    console.error("Error uploading file:", err);
    alert("Failed to analyze uploaded .eml file. Check console for details.");
  }
}

function renderCaseData(data) {
  currentCase = data;

  // 1. Evidence Metadata Strip
  document.getElementById("meta-case-id").innerText = `CASE-${data.case_id}`;
  document.getElementById("meta-sha256").innerText = data.evidence_sha256;
  document.getElementById("meta-sha256").title = data.evidence_sha256;
  document.getElementById("meta-sender").innerText = `${data.headers.From || 'Unknown'}`;
  document.getElementById("meta-origin-ip").innerText = `${data.originating_ip || 'Internal'} (${data.hops[0]?.country || 'Unknown'})`;

  // 2. Fraud Score Gauge & Badge
  const score = data.threat_scoring.fraud_score;
  document.getElementById("score-value").innerText = score.toFixed(1);
  const badgeTier = document.getElementById("badge-risk-tier");
  badgeTier.innerText = data.threat_scoring.risk_tier;

  // Circle meter calculation (circumference = 264)
  const circle = document.getElementById("score-circle");
  const offset = 264 - (score / 100) * 264;
  circle.style.strokeDashoffset = offset;

  if (score >= 75) {
    circle.setAttribute("class", "text-red-500 fill-none stroke-round transition-all duration-1000");
    badgeTier.className = "px-2.5 py-0.5 text-[11px] font-bold font-mono uppercase rounded-full bg-red-950 text-red-400 border border-red-800";
  } else if (score >= 50) {
    circle.setAttribute("class", "text-orange-500 fill-none stroke-round transition-all duration-1000");
    badgeTier.className = "px-2.5 py-0.5 text-[11px] font-bold font-mono uppercase rounded-full bg-orange-950 text-orange-400 border border-orange-800";
  } else if (score >= 25) {
    circle.setAttribute("class", "text-amber-500 fill-none stroke-round transition-all duration-1000");
    badgeTier.className = "px-2.5 py-0.5 text-[11px] font-bold font-mono uppercase rounded-full bg-amber-950 text-amber-400 border border-amber-800";
  } else {
    circle.setAttribute("class", "text-emerald-500 fill-none stroke-round transition-all duration-1000");
    badgeTier.className = "px-2.5 py-0.5 text-[11px] font-bold font-mono uppercase rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800";
  }

  // Mini Protocol & Evasion Badges
  const miniAuth = document.getElementById("mini-auth-status");
  miniAuth.innerText = data.protocols.overall_authentication_pass ? "PASS" : "FAIL";
  miniAuth.className = `font-mono text-xs font-bold ${data.protocols.overall_authentication_pass ? "text-emerald-400" : "text-red-400"}`;

  const miniDeobf = document.getElementById("mini-deobf-status");
  miniDeobf.innerText = data.deobfuscation.evasion_detected ? "EVASION" : "CLEAN";
  miniDeobf.className = `font-mono text-xs font-bold ${data.deobfuscation.evasion_detected ? "text-red-400" : "text-emerald-400"}`;

  const miniQuish = document.getElementById("mini-quish-status");
  miniQuish.innerText = data.quishing.is_quishing_detected ? "DETECTED" : "NONE";
  miniQuish.className = `font-mono text-xs font-bold ${data.quishing.is_quishing_detected ? "text-red-400" : "text-muted-foreground"}`;

  // 3. Risk Meters & Radar
  const m = data.threat_scoring.metrics;
  updateRiskMeter("auth", m.authentication_risk);
  updateRiskMeter("header", m.header_anomaly_risk);
  updateRiskMeter("deobf", m.obfuscation_risk);
  updateRiskMeter("nlp", m.nlp_manipulation_risk);
  updateRiskMeter("net", m.infrastructure_risk);

  if (radarChart) {
    radarChart.data.datasets[0].data = [
      m.authentication_risk,
      m.header_anomaly_risk,
      m.obfuscation_risk,
      m.nlp_manipulation_risk,
      m.quishing_risk,
      m.infrastructure_risk
    ];
    radarChart.update();
  }

  // 4. Populate Hop Map & Timeline Table
  renderHopMap(data.hops);

  // 5. De-Obfuscation Inspector
  renderDeobfuscation(data.deobfuscation, data.body_preview);

  // 6. RFC Headers & Protocol Matrix
  renderProtocols(data.protocols, data.headers);

  // 7. IoCs Table
  renderIoCs(data.iocs);

  // 8. Findings & Citations Cards
  renderFindings(data.threat_scoring.findings);

  if (window.lucide) {
    window.lucide.createIcons();
  }
}

function updateRiskMeter(key, value) {
  const valElem = document.getElementById(`meter-val-${key}`);
  const barElem = document.getElementById(`meter-bar-${key}`);
  if (valElem && barElem) {
    valElem.innerText = `${Math.round(value)}%`;
    barElem.style.width = `${Math.min(100, Math.max(0, value))}%`;
    if (value >= 75) {
      barElem.className = "bg-red-500 h-full rounded-full transition-all duration-700";
      valElem.className = "font-mono text-red-400 font-bold";
    } else if (value >= 40) {
      barElem.className = "bg-amber-500 h-full rounded-full transition-all duration-700";
      valElem.className = "font-mono text-amber-400 font-bold";
    } else {
      barElem.className = "bg-emerald-500 h-full rounded-full transition-all duration-700";
      valElem.className = "font-mono text-emerald-400 font-bold";
    }
  }
}

function renderHopMap(hops) {
  if (!leafletMap) return;

  // Clear previous markers & polylines
  mapMarkers.forEach(m => leafletMap.removeLayer(m));
  mapMarkers = [];
  if (mapPolyline) {
    leafletMap.removeLayer(mapPolyline);
    mapPolyline = null;
  }

  const latLngs = [];
  const tableBody = document.getElementById("hops-table-body");
  if (tableBody) tableBody.innerHTML = "";

  hops.forEach((hop) => {
    const lat = hop.latitude;
    const lon = hop.longitude;
    const isOrigin = hop.is_originating_hop;

    if (lat && lon && lat !== 0.0) {
      latLngs.push([lat, lon]);

      const markerColor = isOrigin ? "#ef4444" : "#10b981";
      const customIcon = L.divIcon({
        className: "cyber-marker-pulse",
        html: `<div class="marker-inner" style="background: ${markerColor}; border-color: #fff;"></div>`,
        iconSize: [20, 20],
        iconAnchor: [10, 10]
      });

      const marker = L.marker([lat, lon], { icon: customIcon }).addTo(leafletMap);
      marker.bindPopup(`
        <div class="text-xs font-mono p-1">
          <strong class="${isOrigin ? 'text-red-400' : 'text-emerald-400'}">Hop ${hop.hop_sequence} (${isOrigin ? 'Origin' : 'Transit'})</strong><br/>
          <strong>IP:</strong> ${hop.relay_ip}<br/>
          <strong>Location:</strong> ${hop.city}, ${hop.country}<br/>
          <strong>ASN:</strong> ${hop.asn} (${hop.isp})<br/>
          <strong>Type:</strong> ${hop.infra_type}
        </div>
      `);
      mapMarkers.push(marker);
    }

    // Append table row
    if (tableBody) {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-muted/40 transition-colors";
      tr.innerHTML = `
        <td class="p-3 font-bold ${isOrigin ? 'text-red-400' : 'text-cyan-400'}">#${hop.hop_sequence}</td>
        <td class="p-3 max-w-xs truncate" title="${hop.from_mta}">${hop.from_mta}</td>
        <td class="p-3 max-w-xs truncate" title="${hop.by_mta}">${hop.by_mta}</td>
        <td class="p-3 font-semibold ${isOrigin ? 'text-amber-300' : 'text-slate-300'}">${hop.relay_ip || 'N/A'}</td>
        <td class="p-3">${hop.city || '—'}, ${hop.country || '—'} (${hop.isp || 'Internal'})</td>
        <td class="p-3">
          <span class="px-2 py-0.5 rounded-full text-[10px] font-semibold ${hop.is_anonymizer ? 'bg-red-950 text-red-300 border border-red-800' : 'bg-cyber-800 text-slate-300 border border-border'}">
            ${hop.infra_type}
          </span>
        </td>
        <td class="p-3">${hop.latency_seconds.toFixed(2)}s</td>
      `;
      tableBody.appendChild(tr);
    }
  });

  if (latLngs.length > 1) {
    mapPolyline = L.polyline(latLngs, {
      color: "#06b6d4",
      weight: 3,
      opacity: 0.85,
      dashArray: "6, 8"
    }).addTo(leafletMap);
    leafletMap.fitBounds(mapPolyline.getBounds(), { padding: [40, 40] });
  } else if (latLngs.length === 1) {
    leafletMap.setView(latLngs[0], 4);
  }
}

function renderDeobfuscation(deobf, rawBody) {
  document.getElementById("raw-body-content").innerText = rawBody || "(No plain body content)";
  document.getElementById("normalized-body-content").innerText = deobf.normalized_text || "(No normalized content)";

  document.getElementById("badge-zwsp-count").innerText = `${deobf.zero_width_count} ZWSP Found`;
  document.getElementById("badge-homoglyph-count").innerText = `${deobf.homoglyphs_detected.length} Homoglyphs Unmasked`;

  const container = document.getElementById("homoglyphs-detail-container");
  container.innerHTML = "";

  const lookalike = deobf.domain_lookalike;
  if (lookalike && lookalike.is_lookalike) {
    const d = document.createElement("div");
    d.className = "p-3 rounded-lg bg-red-950/40 border border-red-900 flex items-center justify-between";
    d.innerHTML = `
      <div>
        <span class="font-bold text-red-400">Deceptive Lookalike Domain Identified:</span>
        <span class="text-white ml-2 font-mono font-semibold">${lookalike.original_domain}</span>
        <span class="text-muted-foreground ml-2">mimics target brand</span>
        <span class="text-cyan-300 ml-1 font-bold font-mono">${lookalike.closest_brand}</span>
      </div>
      <span class="font-mono text-xs text-red-300 px-2 py-0.5 rounded-full bg-red-900 border border-red-700">Edit Dist: ${lookalike.edit_distance}</span>
    `;
    container.appendChild(d);
  }

  if (deobf.homoglyphs_detected.length > 0) {
    deobf.homoglyphs_detected.forEach(h => {
      const item = document.createElement("div");
      item.className = "p-2.5 rounded-lg bg-cyber-850 border border-border flex items-center justify-between";
      item.innerHTML = `
        <div class="flex items-center space-x-2">
          <span class="font-mono text-amber-400 font-bold text-sm bg-cyber-900 px-2 py-0.5 rounded border border-border">'${h.char}'</span>
          <span class="text-muted-foreground text-xs">Normalized to Latin:</span>
          <span class="font-mono text-cyan-300 font-bold text-sm bg-cyber-900 px-2 py-0.5 rounded border border-border">'${h.replacement}'</span>
          <span class="text-slate-500 font-mono text-xs">(${h.unicode} - ${h.name})</span>
        </div>
        <span class="text-[11px] text-muted-foreground font-mono">Index @ ${h.position}</span>
      `;
      container.appendChild(item);
    });
  } else if (!lookalike?.is_lookalike) {
    container.innerHTML = `<span class="text-muted-foreground italic text-xs">No Unicode homoglyphs or zero-width evasions identified in this sample.</span>`;
  }
}

function renderProtocols(proto, headers) {
  // SPF Card
  const spfBadge = document.getElementById("proto-spf-badge");
  const spfCard = document.getElementById("card-spf");
  spfBadge.innerText = proto.spf.status.toUpperCase();
  if (proto.spf.status === "pass") {
    spfBadge.className = "px-2.5 py-0.5 font-mono text-xs font-bold rounded-full bg-emerald-900 text-emerald-200 border border-emerald-700";
    spfCard.className = "p-4 rounded-lg border bg-cyber-850 border-emerald-900/80";
  } else {
    spfBadge.className = "px-2.5 py-0.5 font-mono text-xs font-bold rounded-full bg-red-900 text-red-200 border border-red-700";
    spfCard.className = "p-4 rounded-lg border bg-cyber-850 border-red-900/80";
  }

  // DKIM Card
  const dkimBadge = document.getElementById("proto-dkim-badge");
  const dkimCard = document.getElementById("card-dkim");
  dkimBadge.innerText = proto.dkim.status.toUpperCase();
  if (proto.dkim.status === "pass") {
    dkimBadge.className = "px-2.5 py-0.5 font-mono text-xs font-bold rounded-full bg-emerald-900 text-emerald-200 border border-emerald-700";
    dkimCard.className = "p-4 rounded-lg border bg-cyber-850 border-emerald-900/80";
  } else {
    dkimBadge.className = "px-2.5 py-0.5 font-mono text-xs font-bold rounded-full bg-red-900 text-red-200 border border-red-700";
    dkimCard.className = "p-4 rounded-lg border bg-cyber-850 border-red-900/80";
  }

  // DMARC Card
  const dmarcBadge = document.getElementById("proto-dmarc-badge");
  const dmarcCard = document.getElementById("card-dmarc");
  dmarcBadge.innerText = proto.dmarc.status.toUpperCase();
  if (proto.dmarc.status === "pass") {
    dmarcBadge.className = "px-2.5 py-0.5 font-mono text-xs font-bold rounded-full bg-emerald-900 text-emerald-200 border border-emerald-700";
    dmarcCard.className = "p-4 rounded-lg border bg-cyber-850 border-emerald-900/80";
  } else {
    dmarcBadge.className = "px-2.5 py-0.5 font-mono text-xs font-bold rounded-full bg-red-900 text-red-200 border border-red-700";
    dmarcCard.className = "p-4 rounded-lg border bg-cyber-850 border-red-900/80";
  }

  // Raw Headers Inspector
  const listContainer = document.getElementById("headers-key-value-list");
  listContainer.innerHTML = "";
  Object.entries(headers).forEach(([k, v]) => {
    const row = document.createElement("div");
    row.className = "flex py-1.5 border-b border-border last:border-0 items-start";
    row.innerHTML = `<span class="text-cyan-400 font-bold w-40 shrink-0 select-all">${k}:</span><span class="text-slate-300 break-all select-all font-mono">${v}</span>`;
    listContainer.appendChild(row);
  });
}

function renderIoCs(iocs) {
  document.getElementById("ioc-badge-count").innerText = iocs.length;
  const tbody = document.getElementById("iocs-table-body");
  tbody.innerHTML = "";

  iocs.forEach(ioc => {
    const tr = document.createElement("tr");
    tr.className = "hover:bg-muted/40 transition-colors";

    let riskBadge = "bg-cyber-800 text-slate-300 border border-border";
    if (ioc.risk === "Critical") riskBadge = "bg-red-950 text-red-300 border border-red-800";
    else if (ioc.risk === "High") riskBadge = "bg-orange-950 text-orange-300 border border-orange-800";
    else if (ioc.risk === "Medium") riskBadge = "bg-amber-950 text-amber-300 border border-amber-800";
    else if (ioc.risk === "Low") riskBadge = "bg-emerald-950 text-emerald-300 border border-emerald-800";

    tr.innerHTML = `
      <td class="p-3 font-bold text-cyan-400">${ioc.type}</td>
      <td class="p-3 font-semibold select-all text-slate-200">${ioc.value}</td>
      <td class="p-3"><span class="px-2.5 py-0.5 rounded-full text-[10px] font-bold ${riskBadge}">${ioc.risk}</span></td>
      <td class="p-3 text-muted-foreground">${ioc.category}</td>
      <td class="p-3 text-slate-300">${ioc.context}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderFindings(findings) {
  const container = document.getElementById("findings-cards-container");
  container.innerHTML = "";

  if (!findings || findings.length === 0) {
    container.innerHTML = `<div class="p-4 rounded-lg bg-cyber-850 text-muted-foreground text-xs italic border border-border">No suspicious adversarial findings detected in this record.</div>`;
    return;
  }

  findings.forEach(f => {
    const card = document.createElement("div");
    card.className = "p-4 rounded-lg bg-cyber-850 border border-border flex items-start space-x-3.5 hover:border-slate-700 transition-colors";
    card.innerHTML = `
      <span class="px-2.5 py-1 rounded-md bg-cyan-950 text-cyan-300 border border-cyan-800/80 font-mono text-xs font-bold shrink-0">
        ${f.id}
      </span>
      <div>
        <h4 class="text-xs font-bold text-white mb-1">${f.category}</h4>
        <p class="text-xs text-slate-300 leading-relaxed">${f.description}</p>
      </div>
    `;
    container.appendChild(card);
  });
}

async function openCertificateModal() {
  if (!currentCase) return;
  try {
    const res = await fetch("/api/evidence/certificate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        case_id: currentCase.case_id,
        investigator_name: "Inspector Rakesh Rawat",
        designation: "Senior Cyber Forensic Examiner",
        organization: "Cyber Crime Forensic Investigation Division"
      })
    });
    if (!res.ok) throw new Error(`Certificate request failed HTTP ${res.status}`);
    const cert = await res.json();
    document.getElementById("cert-raw-text").innerText = cert.certificate_text;
    const certModal = document.getElementById("cert-modal");
    certModal.classList.remove("hidden");
    // Accessibility focus management
    certModal.focus();
  } catch (err) {
    console.error("Error generating legal certificate:", err);
    alert("Could not generate Section 63 BSA certificate.");
  }
}

function exportIoCs(format) {
  if (!currentCase) return;
  window.open(`/api/evidence/export/${currentCase.case_id}?format=${format}`, "_blank");
}
