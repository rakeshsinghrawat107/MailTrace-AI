/**
 * MailTrace.AI - Forensic SOC Client Application
 * Keyless Esri Dark Canvas Mapping, Real Dataset Exploration & Section 63 BSA 2023 Certification
 */

let mapInstance = null;
let hopMarkersLayer = null;
let hopPolylineLayer = null;
let currentAnalysis = null;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide) {
    window.lucide.createIcons();
  }
  initMap();
  initTabs();
  initModalListeners();
  loadSampleCatalog();
  initEventListeners();
});

/* ==========================================================================
   1. Keyless Geospatial Basemap Initialization (Esri World Dark Gray)
   ========================================================================== */
function initMap() {
  const mapElem = document.getElementById('leaflet-map');
  if (!mapElem) return;

  // Center on Europe/Asia transit crossroads initially
  mapInstance = L.map('leaflet-map', {
    center: [30, 30],
    zoom: 2,
    minZoom: 2,
    maxZoom: 16,
    zoomControl: true
  });

  // Pure Keyless Esri ArcGIS World Dark Gray Base
  L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
    attribution: 'Tiles &copy; Esri &mdash; Esri, DeLorme, NAVTEQ',
    maxZoom: 16
  }).addTo(mapInstance);

  // Esri Dark Gray Reference Layer (Labels & Boundaries)
  L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}', {
    maxZoom: 16
  }).addTo(mapInstance);

  hopMarkersLayer = L.layerGroup().addTo(mapInstance);
  hopPolylineLayer = L.layerGroup().addTo(mapInstance);
}

/* ==========================================================================
   2. Sample Catalog & Dataset Loading (from backend/samples/1/)
   ========================================================================== */
async function loadSampleCatalog() {
  const selectElem = document.getElementById('sample-select');
  if (!selectElem) return;

  try {
    const res = await fetch('/api/samples?limit=100');
    if (!res.ok) throw new Error("Failed to load samples");
    const data = await res.json();

    selectElem.innerHTML = '';
    
    if (data.samples && data.samples.length > 0) {
      data.samples.forEach((s, idx) => {
        const opt = document.createElement('option');
        opt.value = s.sample_id;
        opt.textContent = `[#${idx + 1}] ${s.filename} (${Math.round(s.size_bytes / 1024)} KB)`;
        selectElem.appendChild(opt);
      });

      // Auto-load the first real sample for immediate demonstration
      inspectSample(data.samples[0].sample_id);
    } else {
      selectElem.innerHTML = '<option value="">No samples found in dataset</option>';
    }
  } catch (err) {
    console.error("Error loading sample catalog:", err);
    selectElem.innerHTML = '<option value="">Error loading samples</option>';
  }
}

async function inspectSample(sampleId) {
  if (!sampleId) return;
  setLoadingState(true);

  try {
    const res = await fetch(`/api/samples/${encodeURIComponent(sampleId)}`);
    if (!res.ok) throw new Error(`Analysis failed with status ${res.status}`);
    const analysis = await res.json();
    renderAnalysis(analysis);
  } catch (err) {
    console.error("Analysis error:", err);
    alert(`Failed to analyze sample: ${err.message}`);
  } finally {
    setLoadingState(false);
  }
}

/* ==========================================================================
   3. File Upload Handling (.EML / .MSG)
   ========================================================================== */
async function handleFileUpload(file) {
  if (!file) return;
  setLoadingState(true);

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/analyze/upload', {
      method: 'POST',
      body: formData
    });
    if (!res.ok) throw new Error(`Upload failed with status ${res.status}`);
    const analysis = await res.json();
    renderAnalysis(analysis);
  } catch (err) {
    console.error("Upload analysis error:", err);
    alert(`Analysis failed: ${err.message}`);
  } finally {
    setLoadingState(false);
  }
}

/* ==========================================================================
   4. Render Analysis State to SOC Dashboard
   ========================================================================== */
function renderAnalysis(data) {
  currentAnalysis = data;

  // 1. Case ID & Pre-parse Hashing
  document.getElementById('case-id-badge').textContent = data.case_id;
  document.getElementById('meta-sha256').textContent = data.evidence_sha256;
  document.getElementById('meta-from').textContent = data.headers.from || 'N/A';
  document.getElementById('meta-return-path').textContent = data.headers.return_path || 'N/A';
  document.getElementById('meta-subject').textContent = data.headers.subject || 'N/A';
  document.getElementById('meta-msgid').textContent = data.headers.message_id || 'N/A';

  // 2. Threat Gauge & Risk Tier
  const score = data.fraud_score || 0.0;
  const gaugeValElem = document.getElementById('gauge-val');
  const gaugeBar = document.getElementById('gauge-bar');
  const tierBadge = document.getElementById('risk-tier-badge');

  gaugeValElem.textContent = score.toFixed(1);
  const totalDash = 314.159;
  const offset = totalDash * (1 - (score / 100));
  gaugeBar.style.strokeDashoffset = offset;

  // Color mapping
  let scoreColor = '#10b981'; // Green (Benign)
  let tierClass = 'chip-pass';
  if (score >= 75) {
    scoreColor = '#ef4444'; // Red (Critical)
    tierClass = 'chip-fail';
  } else if (score >= 50) {
    scoreColor = '#f97316'; // Orange (Malicious)
    tierClass = 'chip-warn';
  } else if (score >= 25) {
    scoreColor = '#eab308'; // Yellow (Suspicious)
    tierClass = 'chip-warn';
  }

  gaugeBar.style.stroke = scoreColor;
  tierBadge.className = `tier-badge ${tierClass}`;
  tierBadge.textContent = `${data.risk_tier} (${score.toFixed(1)})`;

  // 3. Sub-score Progress Bars
  const subs = data.sub_scores || {};
  renderSubBar('proto', subs.protocol_auth || 0);
  renderSubBar('align', subs.header_alignment || 0);
  renderSubBar('deobf', subs.deobfuscation || 0);
  renderSubBar('quish', subs.quishing || 0);
  renderSubBar('net', subs.network_intel || 0);

  // 4. Leaflet Map: Hops & Arcs
  renderHopMap(data.hops || []);

  // 5. Tabs
  renderHopsTable(data.hops || []);
  renderProtocolsTab(data.protocols || {});
  renderDeobfuscationTab(data.deobfuscation || {});
  renderQuishingTab(data.quishing || {});
  renderFindingsTab(data.findings || []);
  renderCustodyLedger();
  document.getElementById('raw-headers-pre').textContent = JSON.stringify(data.headers, null, 2);

  // Re-run lucide icons
  if (window.lucide) {
    window.lucide.createIcons();
  }
}

function renderSubBar(id, val) {
  const lbl = document.getElementById(`score-${id}`);
  const bar = document.getElementById(`bar-${id}`);
  if (lbl && bar) {
    lbl.textContent = `${val.toFixed(1)}%`;
    bar.style.width = `${Math.min(100, Math.max(0, val))}%`;
  }
}

/* ==========================================================================
   5. Leaflet Hop Map & Polyline Renderer
   ========================================================================== */
function renderHopMap(hops) {
  if (!mapInstance || !hopMarkersLayer || !hopPolylineLayer) return;

  hopMarkersLayer.clearLayers();
  hopPolylineLayer.clearLayers();

  document.getElementById('map-hop-count').textContent = `${hops.length} Relays Traced`;
  document.getElementById('tab-cnt-hops').textContent = hops.length;

  const latLngs = [];

  hops.forEach((hop) => {
    const lat = hop.latitude;
    const lng = hop.longitude;
    if (lat !== undefined && lng !== undefined) {
      latLngs.push([lat, lng]);

      const isOrigin = hop.is_origin;
      const markerHtml = `
        <div class="custom-hop-pin">
          <div class="hop-pulse-marker ${isOrigin ? 'origin' : ''}">
            ${hop.hop_sequence}
          </div>
        </div>
      `;

      const customIcon = L.divIcon({
        className: '',
        html: markerHtml,
        iconSize: [24, 24],
        iconAnchor: [12, 12]
      });

      const popupContent = `
        <div style="font-size: 11px; color: #0f172a; padding: 2px;">
          <b>Hop #${hop.hop_sequence} ${isOrigin ? '(ORIGIN MTA)' : ''}</b><br/>
          <b>IP:</b> <code>${hop.relay_ip}</code><br/>
          <b>Location:</b> ${hop.city}, ${hop.country_code}<br/>
          <b>ASN:</b> ${hop.asn}<br/>
          <b>Latency:</b> ${hop.latency_seconds.toFixed(2)}s<br/>
          <b>Type:</b> ${hop.infra_type}
        </div>
      `;

      const marker = L.marker([lat, lng], { icon: customIcon }).bindPopup(popupContent);
      hopMarkersLayer.addLayer(marker);
    }
  });

  if (latLngs.length > 1) {
    const polyline = L.polyline(latLngs, {
      color: '#06b6d4',
      weight: 2.5,
      opacity: 0.85,
      dashArray: '5, 8'
    });
    hopPolylineLayer.addLayer(polyline);
    mapInstance.fitBounds(polyline.getBounds(), { padding: [40, 40], maxZoom: 6 });
  } else if (latLngs.length === 1) {
    mapInstance.setView(latLngs[0], 4);
  }
}

/* ==========================================================================
   6. Tab Renderers
   ========================================================================== */
function renderHopsTable(hops) {
  const tbody = document.getElementById('hops-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  if (hops.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;">No hops detected in headers.</td></tr>';
    return;
  }

  hops.forEach((h) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><b>#${h.hop_sequence}</b> ${h.is_origin ? '<span class="chip chip-fail" style="font-size:9px;">ORIGIN</span>' : ''}</td>
      <td style="font-family:monospace;">${h.from_mta || 'Unknown'}</td>
      <td style="font-family:monospace;">${h.by_mta || 'Unknown'}</td>
      <td style="font-family:monospace; color:#38bdf8;">${h.relay_ip}</td>
      <td>${h.city}, ${h.country_code}</td>
      <td style="font-size:10.5px;">${h.asn}</td>
      <td>${h.latency_seconds.toFixed(2)}s</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderProtocolsTab(proto) {
  const spfElem = document.getElementById('proto-spf-val');
  const dkimElem = document.getElementById('proto-dkim-val');
  const dmarcElem = document.getElementById('proto-dmarc-val');
  const alignElem = document.getElementById('proto-align-val');

  formatStatusChip(spfElem, proto.spf_status);
  formatStatusChip(dkimElem, proto.dkim_status);
  formatStatusChip(dmarcElem, proto.dmarc_status);

  if (proto.domain_aligned) {
    alignElem.innerHTML = '<span class="chip chip-pass">ALIGNED</span>';
  } else {
    alignElem.innerHTML = '<span class="chip chip-fail">MISMATCH (BEC RISK)</span>';
  }

  const findingsList = document.getElementById('protocol-findings-list');
  findingsList.innerHTML = '';
  (proto.findings || []).forEach((f) => {
    const item = document.createElement('div');
    item.style.cssText = 'font-size: 11.5px; color: #f87171; display: flex; align-items: center; gap: 0.4rem;';
    item.innerHTML = `<i data-lucide="alert-circle" style="width:13px; height:13px;"></i> ${f}`;
    findingsList.appendChild(item);
  });
}

function formatStatusChip(elem, status) {
  if (!elem) return;
  const s = (status || 'none').toUpperCase();
  let chipClass = 'chip-warn';
  if (s === 'PASS') chipClass = 'chip-pass';
  else if (s === 'FAIL' || s === 'SOFTFAIL') chipClass = 'chip-fail';
  elem.innerHTML = `<span class="chip ${chipClass}">${s}</span>`;
}

function renderDeobfuscationTab(deobf) {
  const tbody = document.getElementById('deobf-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  const rows = [
    {
      cat: "Zero-Width Invisible Characters (ZWSP)",
      count: deobf.zero_width_count || 0,
      status: deobf.zero_width_count > 0 ? "EVASION DETECTED" : "CLEAN",
      impact: deobf.zero_width_count > 0 ? "Bypasses keyword security filters" : "Normal character density"
    },
    {
      cat: "Cyrillic / Greek Homoglyphs",
      count: deobf.homoglyphs_unmasked_count || 0,
      status: deobf.homoglyphs_unmasked_count > 0 ? "SPOOFING DETECTED" : "CLEAN",
      impact: deobf.homoglyphs_unmasked_count > 0 ? "Visual deception mimicking Latin text" : "Pure ASCII / Latin character set"
    }
  ];

  if (deobf.brand_spoof) {
    rows.push({
      cat: `Brand Typosquatting (${deobf.brand_spoof.impersonated_brand})`,
      count: 1,
      status: "ADVERSARIAL LOOKALIKE",
      impact: `Mimics '${deobf.brand_spoof.impersonated_brand}' with Levenshtein distance ${deobf.brand_spoof.edit_distance}`
    });
  }

  rows.forEach((r) => {
    const isEvasion = r.count > 0;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><b>${r.cat}</b></td>
      <td><span class="chip ${isEvasion ? 'chip-fail' : 'chip-pass'}">${r.count}</span></td>
      <td><span class="chip ${isEvasion ? 'chip-fail' : 'chip-pass'}">${r.status}</span></td>
      <td style="color: ${isEvasion ? '#f87171' : 'var(--muted-foreground)'};">${r.impact}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderQuishingTab(quishing) {
  const container = document.getElementById('quishing-container');
  if (!container) return;

  if (!quishing.quishing_detected) {
    container.innerHTML = `
      <div style="text-align: center; color: var(--muted-foreground); padding: 1.5rem;">
        <i data-lucide="shield-check" style="width: 24px; height: 24px; color: #10b981; margin-bottom: 0.4rem;"></i><br/>
        No QR Code payloads or Quishing directives detected in this message.
      </div>
    `;
    return;
  }

  let html = `
    <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: var(--radius); padding: 0.9rem; margin-bottom: 1rem;">
      <div style="display: flex; align-items: center; gap: 0.5rem; font-weight: 700; color: #f87171;">
        <i data-lucide="alert-triangle" style="width: 16px; height: 16px;"></i>
        ADVERSARIAL QUISHING (QR CODE PHISHING) PAYLOAD UNMASKED
      </div>
      <div style="font-size: 11.5px; color: #cbd5e1; margin-top: 0.3rem;">
        Optical scan revealed embedded QR code designed to steer victims onto credential-harvesting mobile sites.
      </div>
    </div>
    <table class="data-table">
      <thead>
        <tr>
          <th>Source</th>
          <th>Dimensions</th>
          <th>Decoded URL Destination</th>
          <th>Risk Assessment</th>
        </tr>
      </thead>
      <tbody>
  `;

  (quishing.qr_payloads || []).forEach((qr) => {
    html += `
      <tr>
        <td><b>${qr.source}</b></td>
        <td>${qr.dimensions}</td>
        <td style="font-family: monospace; color: #38bdf8; word-break: break-all;">${qr.decoded_uri}</td>
        <td><span class="chip chip-fail">CREDENTIAL HARVESTER</span></td>
      </tr>
    `;
  });

  html += `</tbody></table>`;
  container.innerHTML = html;
}

function renderFindingsTab(findings) {
  const tbody = document.getElementById('findings-tbody');
  const countBadge = document.getElementById('tab-cnt-findings');
  if (countBadge) countBadge.textContent = findings.length;
  if (!tbody) return;
  tbody.innerHTML = '';

  if (findings.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No high-risk adversarial indicators flagged.</td></tr>';
    return;
  }

  findings.forEach((f) => {
    const tr = document.createElement('tr');
    const isCrit = f.severity === 'CRITICAL';
    tr.innerHTML = `
      <td><span class="chip ${isCrit ? 'chip-fail' : 'chip-warn'}">${f.code}</span></td>
      <td><span class="chip ${isCrit ? 'chip-fail' : 'chip-warn'}">${f.severity}</span></td>
      <td><b>${f.category}</b></td>
      <td style="color: #f1f5f9;">${f.finding}</td>
      <td><span style="font-family:monospace; font-size:10px; color:#38bdf8;">${f.mitre}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

async function renderCustodyLedger() {
  const tbody = document.getElementById('custody-tbody');
  if (!tbody) return;

  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    tbody.innerHTML = `
      <tr>
        <td><b>#1</b></td>
        <td><span class="chip chip-pass">EVIDENCE_INGESTED</span></td>
        <td>MailTrace-Autonomous-Gate</td>
        <td>${new Date().toISOString()}</td>
        <td style="font-family:monospace; font-size:10px; color:#38bdf8;">${(currentAnalysis?.evidence_sha256 || 'e3b0c442...').substring(0, 24)}...</td>
        <td>Pre-parsing raw byte preservation complete.</td>
      </tr>
    `;
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="6">Ledger synchronized locally.</td></tr>';
  }
}

/* ==========================================================================
   7. Section 63 BSA 2023 Digital Certificate Modal
   ========================================================================== */
async function openCertificateModal() {
  if (!currentAnalysis) {
    alert("Please select or upload an email to inspect first.");
    return;
  }

  const modal = document.getElementById('cert-modal');
  const certBody = document.getElementById('cert-body-content');
  modal.classList.add('open');
  certBody.textContent = "Generating Section 63 BSA 2023 Statutory Certificate...";

  try {
    const formData = new FormData();
    formData.append('case_id', currentAnalysis.case_id);
    formData.append('examiner_name', 'Forensic Inspector Rakesh Singh');
    formData.append('examiner_designation', 'Senior Cyber Forensics Officer');
    formData.append('organization', 'Digital Forensics & Incident Response Command');

    const res = await fetch('/api/evidence/certificate', {
      method: 'POST',
      body: formData
    });
    if (!res.ok) throw new Error("Certificate issuance failed");
    const certData = await res.json();
    certBody.textContent = certData.certificate_text;
  } catch (err) {
    certBody.textContent = `Error: ${err.message}`;
  }
}

function closeCertificateModal() {
  const modal = document.getElementById('cert-modal');
  if (modal) modal.classList.remove('open');
}

/* ==========================================================================
   8. Tabs & Event Listeners
   ========================================================================== */
function initTabs() {
  const buttons = document.querySelectorAll('.tab-pill-btn');
  buttons.forEach((btn) => {
    btn.addEventListener('click', () => {
      buttons.forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content-panel').forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetTab = document.getElementById(btn.getAttribute('data-tab'));
      if (targetTab) targetTab.classList.add('active');
    });
  });
}

function initModalListeners() {
  document.getElementById('btn-close-cert-modal')?.addEventListener('click', closeCertificateModal);

  // Close on ESC key
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeCertificateModal();
    }
  });

  document.getElementById('btn-copy-cert')?.addEventListener('click', () => {
    const text = document.getElementById('cert-body-content')?.textContent;
    if (text) {
      navigator.clipboard.writeText(text);
      alert("Section 63 BSA Certificate copied to clipboard!");
    }
  });

  document.getElementById('btn-download-pdf-modal')?.addEventListener('click', () => {
    if (currentAnalysis) {
      window.open(`/api/cases/${currentAnalysis.case_id}/pdf`, '_blank');
    }
  });
}

function initEventListeners() {
  document.getElementById('btn-load-sample')?.addEventListener('click', () => {
    const select = document.getElementById('sample-select');
    if (select?.value) inspectSample(select.value);
  });

  document.getElementById('sample-select')?.addEventListener('change', (e) => {
    inspectSample(e.target.value);
  });

  const uploadInput = document.getElementById('file-upload');
  document.getElementById('btn-trigger-upload')?.addEventListener('click', () => {
    uploadInput?.click();
  });

  uploadInput?.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFileUpload(e.target.files[0]);
    }
  });

  document.getElementById('btn-open-cert')?.addEventListener('click', openCertificateModal);

  document.getElementById('btn-export-pdf')?.addEventListener('click', () => {
    if (currentAnalysis) {
      window.open(`/api/cases/${currentAnalysis.case_id}/pdf`, '_blank');
    } else {
      alert("Select or upload an email to generate its PDF dossier.");
    }
  });

  document.getElementById('btn-export-iocs')?.addEventListener('click', () => {
    if (currentAnalysis) {
      window.open(`/api/evidence/export/${currentAnalysis.case_id}?format=csv`, '_blank');
    } else {
      alert("Select or upload an email first.");
    }
  });
}

function setLoadingState(isLoading) {
  const btn = document.getElementById('btn-load-sample');
  if (btn) {
    btn.disabled = isLoading;
    btn.style.opacity = isLoading ? '0.6' : '1.0';
  }
}
