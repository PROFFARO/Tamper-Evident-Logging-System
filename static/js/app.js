/**
 * Tamper-Evident Logging System — Frontend Application
 * 
 * Handles all UI interactions, API communication, and dynamic rendering
 * for the security dashboard.
 */

// ============================================================
//  API Client
// ============================================================
const API = {
    async request(url, options = {}) {
        try {
            const res = await fetch(url, {
                headers: { 'Content-Type': 'application/json' },
                ...options
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
            return data;
        } catch (err) {
            console.error(`API Error [${url}]:`, err);
            throw err;
        }
    },
    getLogs: (params = '') => API.request(`/api/logs?${params}`),
    getLog: (id) => API.request(`/api/logs/${id}`),
    addLog: (data) => API.request('/api/logs', { method: 'POST', body: JSON.stringify(data) }),
    getStats: () => API.request('/api/stats'),
    getMeta: () => API.request('/api/meta'),
    verify: () => API.request('/api/verify'),
    verifyEntry: (id) => API.request(`/api/verify/${id}`),
    tamperModify: (id, desc) => API.request(`/api/tamper/modify/${id}`, { method: 'POST', body: JSON.stringify({ description: desc }) }),
    tamperDelete: (id) => API.request(`/api/tamper/delete/${id}`, { method: 'POST' }),
    tamperReorder: (a, b) => API.request('/api/tamper/reorder', { method: 'POST', body: JSON.stringify({ id_a: a, id_b: b }) }),
    createAnchor: () => API.request('/api/anchor', { method: 'POST' }),
    getAnchors: () => API.request('/api/anchors'),
    agentStart: (interval) => API.request('/api/agent/start', { method: 'POST', body: JSON.stringify({ interval }) }),
    agentStop: () => API.request('/api/agent/stop', { method: 'POST' }),
    agentStatus: () => API.request('/api/agent/status'),
    reset: () => API.request('/api/reset', { method: 'POST' }),
    exportReport: () => API.request('/api/export'),
};

// ============================================================
//  State
// ============================================================
let currentSection = 'dashboard';
let currentPage = 1;
let currentFilters = {};
let metaData = null;
let agentRefreshInterval = null;
let lastVerificationReport = null;

// ============================================================
//  Navigation
// ============================================================
function navigateTo(section) {
    currentSection = section;
    document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    
    const sec = document.getElementById(`section-${section}`);
    const nav = document.querySelector(`[data-section="${section}"]`);
    if (sec) sec.classList.add('active');
    if (nav) nav.classList.add('active');
    
    // Close mobile sidebar
    document.getElementById('sidebar')?.classList.remove('open');
    
    // Load section data
    const loaders = {
        'dashboard': loadDashboard,
        'logs': () => loadLogs(1),
        'chain': loadChain,
        'verify': () => {},
        'tamper': () => {},
        'add-log': loadAddLogForm,
        'anchors': loadAnchors,
        'export': () => {},
    };
    (loaders[section] || (() => {}))();
}

// ============================================================
//  Toast Notifications
// ============================================================
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast toast--${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translateX(30px)'; setTimeout(() => toast.remove(), 300); }, 4000);
}

// ============================================================
//  Utility Functions
// ============================================================
function formatTimestamp(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleString('en-GB', { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function truncHash(hash, len = 16) {
    return hash ? hash.substring(0, len) + '...' : '—';
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function getSeverityClass(severity) {
    return `severity--${(severity || 'info').toLowerCase()}`;
}

const DIST_COLORS = ['blue', 'cyan', 'green', 'yellow', 'orange', 'red', 'purple', 'pink'];

// ============================================================
//  Dashboard
// ============================================================
async function loadDashboard() {
    try {
        const stats = await API.getStats();
        
        document.getElementById('totalEntries').textContent = stats.chain_length || 0;
        document.getElementById('securityAlerts').textContent = (stats.event_types?.SECURITY_ALERT || 0);
        document.getElementById('totalAnchors').textContent = stats.total_anchors || 0;
        
        // Chain health — quick verify
        if (stats.chain_length > 0) {
            try {
                const report = await API.verify();
                const health = report.chain_intact ? 'INTACT' : 'BROKEN';
                const el = document.getElementById('chainHealth');
                el.textContent = health;
                el.style.color = report.chain_intact ? 'var(--color-success)' : 'var(--color-danger)';
            } catch { document.getElementById('chainHealth').textContent = '—'; }
        } else {
            document.getElementById('chainHealth').textContent = 'N/A';
        }
        
        // Recent activity
        const activityPanel = document.getElementById('recentActivityPanel');
        if (stats.recent_entries && stats.recent_entries.length > 0) {
            activityPanel.innerHTML = '<div class="activity-list">' + stats.recent_entries.map(e => `
                <div class="activity-item">
                    <div class="activity-dot ${(e.severity || 'info').toLowerCase()}"></div>
                    <div class="activity-content">
                        <div class="activity-desc">${escapeHtml(e.description)}</div>
                        <div class="activity-meta">${formatTimestamp(e.timestamp)} · ${e.source} · ${e.event_type}</div>
                    </div>
                </div>`).join('') + '</div>';
        }
        
        // Event distribution
        const eventPanel = document.getElementById('eventDistPanel');
        if (stats.event_types && Object.keys(stats.event_types).length > 0) {
            const maxVal = Math.max(...Object.values(stats.event_types));
            eventPanel.innerHTML = '<div class="dist-list">' + Object.entries(stats.event_types).map(([type, count], i) => `
                <div class="dist-item">
                    <div class="dist-item__header">
                        <span class="dist-item__label">${type.replace(/_/g, ' ')}</span>
                        <span class="dist-item__count">${count}</span>
                    </div>
                    <div class="dist-bar dist-bar--${DIST_COLORS[i % DIST_COLORS.length]}">
                        <div class="dist-bar__fill" style="width:${(count/maxVal*100).toFixed(1)}%"></div>
                    </div>
                </div>`).join('') + '</div>';
        }
        
        // Severity breakdown
        const sevPanel = document.getElementById('severityPanel');
        if (stats.severities && Object.keys(stats.severities).length > 0) {
            const sevColors = { INFO: 'blue', WARNING: 'yellow', ERROR: 'red', CRITICAL: 'red' };
            const maxSev = Math.max(...Object.values(stats.severities));
            sevPanel.innerHTML = '<div class="dist-list">' + Object.entries(stats.severities).map(([sev, count]) => `
                <div class="dist-item">
                    <div class="dist-item__header">
                        <span class="dist-item__label">${sev}</span>
                        <span class="dist-item__count">${count}</span>
                    </div>
                    <div class="dist-bar dist-bar--${sevColors[sev] || 'blue'}">
                        <div class="dist-bar__fill" style="width:${(count/maxSev*100).toFixed(1)}%"></div>
                    </div>
                </div>`).join('') + '</div>';
        }
    } catch (err) {
        showToast('Failed to load dashboard: ' + err.message, 'error');
    }
}

// ============================================================
//  Agent Controls
// ============================================================
async function updateAgentUI() {
    try {
        const status = await API.agentStatus();
        const badge = document.getElementById('agentStatusBadge');
        const btnLabel = document.getElementById('agentBtnLabel');
        const btn = document.getElementById('btnToggleAgent');
        
        if (status.running) {
            badge.textContent = `Agent Running (${status.cycles_completed} cycles)`;
            badge.className = 'agent-status-badge agent-online';
            btnLabel.textContent = 'Stop Agent';
            btn.classList.remove('btn-primary');
            btn.classList.add('btn-danger');
        } else {
            badge.textContent = 'Agent Offline';
            badge.className = 'agent-status-badge agent-offline';
            btnLabel.textContent = 'Start Agent';
            btn.classList.remove('btn-danger');
            btn.classList.add('btn-primary');
        }
    } catch {}
}

async function toggleAgent() {
    try {
        const status = await API.agentStatus();
        if (status.running) {
            await API.agentStop();
            showToast('Host agent stopped', 'info');
            if (agentRefreshInterval) { clearInterval(agentRefreshInterval); agentRefreshInterval = null; }
        } else {
            await API.agentStart(15);
            showToast('Host agent started — collecting real-time system logs', 'success');
            // Auto-refresh dashboard every 20 seconds while agent is running
            agentRefreshInterval = setInterval(() => {
                if (currentSection === 'dashboard') loadDashboard();
            }, 20000);
        }
        updateAgentUI();
        setTimeout(loadDashboard, 2000);
    } catch (err) {
        showToast('Agent error: ' + err.message, 'error');
    }
}

// ============================================================
//  Log Explorer
// ============================================================
async function loadLogs(page = 1) {
    currentPage = page;
    try {
        const params = new URLSearchParams({ page, per_page: 20 });
        if (currentFilters.event_type) params.set('event_type', currentFilters.event_type);
        if (currentFilters.severity) params.set('severity', currentFilters.severity);
        if (currentFilters.search) params.set('search', currentFilters.search);
        
        const data = await API.getLogs(params.toString());
        
        document.getElementById('logCount').textContent = `${data.total} entries`;
        
        const tbody = document.getElementById('logTableBody');
        if (data.entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:40px;color:var(--text-muted)">No log entries found</td></tr>';
        } else {
            tbody.innerHTML = data.entries.map(e => `
                <tr>
                    <td><span style="font-family:var(--font-mono);font-weight:600">${e.id}</span></td>
                    <td class="timestamp-cell">${formatTimestamp(e.timestamp)}</td>
                    <td><span class="event-badge">${e.event_type}</span></td>
                    <td><span class="severity-badge ${getSeverityClass(e.severity)}">${e.severity}</span></td>
                    <td style="color:var(--text-secondary)">${escapeHtml(e.source)}</td>
                    <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(e.description)}">${escapeHtml(e.description)}</td>
                    <td class="hash-cell" title="${e.current_hash}">${truncHash(e.current_hash)}</td>
                    <td><button class="btn btn-ghost btn-xs" onclick="showEntryModal(${e.id})">Details</button></td>
                </tr>`).join('');
        }
        
        // Pagination
        renderPagination(data.page, data.total_pages, data.total);
    } catch (err) {
        showToast('Failed to load logs: ' + err.message, 'error');
    }
}

function renderPagination(page, totalPages, total) {
    const container = document.getElementById('logPagination');
    if (totalPages <= 1) { container.innerHTML = ''; return; }
    
    let html = `<button ${page <= 1 ? 'disabled' : ''} onclick="loadLogs(${page-1})">← Prev</button>`;
    
    const start = Math.max(1, page - 2);
    const end = Math.min(totalPages, page + 2);
    for (let i = start; i <= end; i++) {
        html += `<button class="${i === page ? 'active' : ''}" onclick="loadLogs(${i})">${i}</button>`;
    }
    
    html += `<button ${page >= totalPages ? 'disabled' : ''} onclick="loadLogs(${page+1})">Next →</button>`;
    container.innerHTML = html;
}

// ============================================================
//  Entry Detail Modal
// ============================================================
async function showEntryModal(id) {
    try {
        const data = await API.getLog(id);
        const e = data.entry;
        
        document.getElementById('modalBody').innerHTML = `
            <div class="modal-row"><span class="modal-label">ID</span><span class="modal-value">${e.id}</span></div>
            <div class="modal-row"><span class="modal-label">Timestamp</span><span class="modal-value">${formatTimestamp(e.timestamp)}</span></div>
            <div class="modal-row"><span class="modal-label">Event Type</span><span class="modal-value">${e.event_type}</span></div>
            <div class="modal-row"><span class="modal-label">Severity</span><span class="modal-value"><span class="severity-badge ${getSeverityClass(e.severity)}">${e.severity}</span></span></div>
            <div class="modal-row"><span class="modal-label">Source</span><span class="modal-value">${escapeHtml(e.source)}</span></div>
            <div class="modal-row"><span class="modal-label">Description</span><span class="modal-value">${escapeHtml(e.description)}</span></div>
            <div class="modal-row"><span class="modal-label">Metadata</span><span class="modal-value mono">${escapeHtml(e.metadata)}</span></div>
            <div class="modal-row"><span class="modal-label">Previous Hash</span><span class="modal-value mono">${e.previous_hash}</span></div>
            <div class="modal-row"><span class="modal-label">Current Hash</span><span class="modal-value mono">${e.current_hash}</span></div>
            <div class="modal-row"><span class="modal-label">HMAC Signature</span><span class="modal-value mono">${e.hmac_signature}</span></div>`;
        
        document.getElementById('entryModal').classList.add('open');
    } catch (err) {
        showToast('Failed to load entry: ' + err.message, 'error');
    }
}

// ============================================================
//  Hash Chain Visualizer
// ============================================================
async function loadChain() {
    try {
        const data = await API.getLogs('page=1&per_page=30');
        const container = document.getElementById('chainContainer');
        
        if (!data.entries || data.entries.length === 0) {
            container.innerHTML = '<div class="empty-state"><p>No chain data to visualize. Add some log entries first.</p></div>';
            return;
        }
        
        // Reverse to show chronological (oldest first)
        const entries = [...data.entries].reverse();
        let html = '';
        
        entries.forEach((e, i) => {
            const isGenesis = e.previous_hash === '0'.repeat(64);
            
            if (i > 0) {
                html += `<div class="chain-link"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></svg></div>`;
            }
            
            html += `
                <div class="chain-block ${isGenesis ? 'genesis' : ''}" onclick="showEntryModal(${e.id})" style="cursor:pointer">
                    <div class="chain-block__header">
                        <span class="chain-block__id">${isGenesis ? '🏁 GENESIS — ' : ''}#${e.id}</span>
                        <span class="event-badge">${e.event_type}</span>
                        <span class="severity-badge ${getSeverityClass(e.severity)}">${e.severity}</span>
                    </div>
                    <div class="chain-block__desc">${escapeHtml(e.description)}</div>
                    <div class="chain-block__hashes">
                        <div class="chain-hash">
                            <div class="chain-hash__label">Previous Hash</div>
                            <div class="chain-hash__value">${isGenesis ? '0000000000000000...' : truncHash(e.previous_hash, 24)}</div>
                        </div>
                        <div class="chain-hash">
                            <div class="chain-hash__label">Current Hash (SHA-256)</div>
                            <div class="chain-hash__value">${truncHash(e.current_hash, 24)}</div>
                        </div>
                    </div>
                </div>`;
        });
        
        container.innerHTML = html;
    } catch (err) {
        showToast('Failed to load chain: ' + err.message, 'error');
    }
}

// ============================================================
//  Integrity Verification
// ============================================================
async function runVerification() {
    const container = document.getElementById('verificationResults');
    container.innerHTML = '<div class="empty-state"><div class="spinner"></div><p style="margin-top:16px">Running full chain verification...</p></div>';
    
    try {
        const report = await API.verify();
        lastVerificationReport = report;
        
        if (report.total_entries === 0) {
            container.innerHTML = '<div class="empty-state"><p>No entries to verify. Add some log entries first.</p></div>';
            return;
        }
        
        const intact = report.chain_intact;
        
        let html = `
            <div class="verification-summary ${intact ? 'intact' : 'tampered'}">
                <div class="verification-summary__header">
                    <div class="verification-summary__icon">
                        ${intact ? 
                            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="24" height="24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>' : 
                            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="24" height="24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
                        }
                    </div>
                    <div>
                        <div class="verification-summary__title">${intact ? 'Chain Integrity Verified' : 'TAMPERING DETECTED!'}</div>
                        <div class="verification-summary__subtitle">${intact ? 'All entries passed verification checks' : `${report.tampered_entries} compromised entries found. First tamper at entry #${report.first_tamper_point}`}</div>
                    </div>
                </div>
                <div class="verification-stats">
                    <div class="v-stat v-stat--ok"><span class="v-stat__value">${report.valid_entries}</span><span class="v-stat__label">Valid Entries</span></div>
                    <div class="v-stat ${report.tampered_entries > 0 ? 'v-stat--fail' : 'v-stat--ok'}"><span class="v-stat__value">${report.tampered_entries}</span><span class="v-stat__label">Tampered</span></div>
                    <div class="v-stat ${report.missing_entries.length > 0 ? 'v-stat--fail' : 'v-stat--ok'}"><span class="v-stat__value">${report.missing_entries.length}</span><span class="v-stat__label">Missing IDs</span></div>
                    <div class="v-stat"><span class="v-stat__value">${report.duration_ms}ms</span><span class="v-stat__label">Duration</span></div>
                </div>
            </div>`;
        
        // Entry-level results
        html += '<div class="verify-entry-list">';
        html += `<div class="verify-entry" style="font-weight:600;background:var(--bg-surface-2);border:none">
            <span>ID</span><span>Description</span><span>Hash</span><span>HMAC</span><span>Seq</span><span>Time</span><span></span></div>`;
        
        report.entries.forEach(e => {
            const valid = e.is_valid;
            html += `
                <div class="verify-entry ${valid ? 'valid' : 'invalid'}" onclick="openVerificationSidebar(${e.entry_id})" style="cursor:pointer" title="Click for detailed mathematical trace">
                    <span class="verify-entry__id">#${e.entry_id}</span>
                    <span style="font-size:.75rem;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">Entry ${e.entry_id}</span>
                    <span class="verify-check ${e.hash_valid ? 'pass' : 'fail'}">${e.hash_valid ? 'PASS' : 'FAIL'}</span>
                    <span class="verify-check ${e.hmac_valid ? 'pass' : 'fail'}">${e.hmac_valid ? 'PASS' : 'FAIL'}</span>
                    <span class="verify-check ${e.sequence_valid ? 'pass' : 'fail'}">${e.sequence_valid ? 'PASS' : 'FAIL'}</span>
                    <span class="verify-check ${e.timestamp_valid ? 'pass' : 'fail'}">${e.timestamp_valid ? 'PASS' : 'FAIL'}</span>
                    <span><button class="btn btn-ghost btn-xs">Details</button></span>
                </div>`;
        });
        html += '</div>';
        
        container.innerHTML = html;
        showToast(intact ? 'Chain integrity verified ✓' : 'Tampering detected!', intact ? 'success' : 'error');
    } catch (err) {
        container.innerHTML = `<div class="empty-state"><p>Verification failed: ${escapeHtml(err.message)}</p></div>`;
        showToast('Verification error: ' + err.message, 'error');
    }
}

function openVerificationSidebar(entryId) {
    if (!lastVerificationReport) return;
    const entryData = lastVerificationReport.entries.find(e => e.entry_id === entryId);
    if (!entryData) return;
    
    document.getElementById('vsId').textContent = entryData.entry_id;
    document.getElementById('vsStatus').innerHTML = entryData.is_valid 
        ? '<span style="color:var(--color-success)">VERIFIED</span>'
        : '<span style="color:var(--color-danger)">TAMPER DETECTED</span>';
        
    document.getElementById('vsExpectedHash').textContent = entryData.expected_hash || 'Genesis block / Not generated';
    document.getElementById('vsStoredHash').textContent = entryData.stored_hash || 'N/A';
    
    document.getElementById('vsHashValid').className = `verify-check ${entryData.hash_valid ? 'pass' : 'fail'}`;
    document.getElementById('vsHashValid').textContent = entryData.hash_valid ? 'PASS' : 'FAIL';
    
    document.getElementById('vsHmacValid').className = `verify-check ${entryData.hmac_valid ? 'pass' : 'fail'}`;
    document.getElementById('vsHmacValid').textContent = entryData.hmac_valid ? 'PASS' : 'FAIL';
    
    document.getElementById('vsSeqValid').className = `verify-check ${entryData.sequence_valid ? 'pass' : 'fail'}`;
    document.getElementById('vsSeqValid').textContent = entryData.sequence_valid ? 'PASS' : 'FAIL';

    document.getElementById('vsTimeValid').className = `verify-check ${entryData.timestamp_valid ? 'pass' : 'fail'}`;
    document.getElementById('vsTimeValid').textContent = entryData.timestamp_valid ? 'PASS' : 'FAIL';
    
    const errorContainer = document.getElementById('vsErrorContainer');
    if (entryData.is_valid) {
        errorContainer.style.display = 'none';
        errorContainer.innerHTML = '';
    } else {
        errorContainer.style.display = 'block';
        let issuesHtml = '<h4 style="margin-bottom:8px;color:#fca5a5;border-bottom:1px solid #450a0a;padding-bottom:4px;">Cryptographic Diagnostic TRACE</h4><ul style="list-style-position:inside;padding-left:0;">';
        entryData.issues.forEach(issue => {
            issuesHtml += `<li style="margin-bottom:6px;background:#450a0a;padding:8px;border-radius:4px;border-left:3px solid #ef4444;"><strong style="color: white; display:block;font-size:0.85rem">${issue.type}</strong> <span style="font-family:var(--font-mono);font-size:0.8rem">${escapeHtml(issue.message)}</span></li>`;
        });
        issuesHtml += '</ul>';
        errorContainer.innerHTML = issuesHtml;
    }
    
    document.getElementById('verificationSidebar').classList.add('open');
}

function closeVerificationSidebar() {
    document.getElementById('verificationSidebar').classList.remove('open');
}

// ============================================================
//  Add Log Entry Form
// ============================================================
async function loadAddLogForm() {
    if (!metaData) {
        try { metaData = await API.getMeta(); } catch { return; }
    }
    
    const typeSelect = document.getElementById('newEventType');
    const sevSelect = document.getElementById('newSeverity');
    
    if (typeSelect.options.length <= 1) {
        metaData.event_types.forEach(t => {
            typeSelect.add(new Option(t.replace(/_/g, ' '), t));
        });
    }
    if (sevSelect.options.length <= 1) {
        metaData.severity_levels.forEach(s => {
            sevSelect.add(new Option(s, s));
        });
    }
}

async function handleAddLog(e) {
    e.preventDefault();
    
    const event_type = document.getElementById('newEventType').value;
    const severity = document.getElementById('newSeverity').value;
    const source = document.getElementById('newSource').value.trim();
    const description = document.getElementById('newDescription').value.trim();
    const metadataStr = document.getElementById('newMetadata').value.trim();
    
    let metadata = {};
    if (metadataStr) {
        try { metadata = JSON.parse(metadataStr); } catch {
            showToast('Invalid JSON in metadata field', 'error');
            return;
        }
    }
    
    try {
        const data = await API.addLog({ event_type, severity, source, description, metadata });
        const entry = data.entry;
        
        showToast(`Entry #${entry.id} added to chain successfully`, 'success');
        
        // Show preview
        const preview = document.getElementById('lastEntryPreview');
        preview.style.display = 'block';
        document.getElementById('lastEntryDetail').innerHTML =
            `ID:             ${entry.id}\n` +
            `Timestamp:      ${entry.timestamp}\n` +
            `Event Type:     ${entry.event_type}\n` +
            `Severity:       ${entry.severity}\n` +
            `Source:         ${entry.source}\n` +
            `Description:    ${entry.description}\n` +
            `Previous Hash:  ${entry.previous_hash}\n` +
            `Current Hash:   ${entry.current_hash}\n` +
            `HMAC Signature: ${entry.hmac_signature}`;
        
        // Reset form
        document.getElementById('addLogForm').reset();
    } catch (err) {
        showToast('Failed to add entry: ' + err.message, 'error');
    }
}

// ============================================================
//  Anchors
// ============================================================
async function loadAnchors() {
    try {
        const data = await API.getAnchors();
        const container = document.getElementById('anchorsContainer');
        
        if (!data.anchors || data.anchors.length === 0) {
            container.innerHTML = '<div class="empty-state"><p>No anchors created yet. Create one to checkpoint the chain state.</p></div>';
            return;
        }
        
        container.innerHTML = data.anchors.map(a => `
            <div class="anchor-card">
                <div class="anchor-card__icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="5" r="3"/><line x1="12" y1="22" x2="12" y2="8"/>
                        <path d="M5 12H2a10 10 0 0 0 20 0h-3"/>
                    </svg>
                </div>
                <div class="anchor-card__info">
                    <h4>Anchor at Entry #${a.entry_id}</h4>
                    <div class="anchor-card__hash">${a.anchor_hash}</div>
                    <div class="anchor-card__meta">${a.entry_count} entries in chain at time of anchor</div>
                </div>
                <div class="anchor-card__time">${formatTimestamp(a.created_at)}</div>
            </div>`).join('');
    } catch (err) {
        showToast('Failed to load anchors: ' + err.message, 'error');
    }
}

// ============================================================
//  Filter Dropdowns
// ============================================================
async function loadFilterOptions() {
    try {
        metaData = await API.getMeta();
        const typeSelect = document.getElementById('filterEventType');
        const sevSelect = document.getElementById('filterSeverity');
        
        metaData.event_types.forEach(t => typeSelect.add(new Option(t.replace(/_/g, ' '), t)));
        metaData.severity_levels.forEach(s => sevSelect.add(new Option(s, s)));
    } catch {}
}

// ============================================================
//  Event Handlers Setup
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            navigateTo(item.dataset.section);
        });
    });
    
    // Mobile menu
    document.getElementById('mobileMenuBtn')?.addEventListener('click', () => {
        document.getElementById('sidebar').classList.toggle('open');
    });
    
    // Close sidebar on overlay click (mobile)
    document.addEventListener('click', (e) => {
        const sidebar = document.getElementById('sidebar');
        const mobileBtn = document.getElementById('mobileMenuBtn');
        if (sidebar.classList.contains('open') && !sidebar.contains(e.target) && !mobileBtn.contains(e.target)) {
            sidebar.classList.remove('open');
        }
    });
    
    // Dashboard actions
    document.getElementById('btnRefreshDashboard')?.addEventListener('click', loadDashboard);
    // Agent toggle
    document.getElementById('btnToggleAgent')?.addEventListener('click', toggleAgent);
    
    // Log filters
    document.getElementById('btnApplyFilters')?.addEventListener('click', () => {
        currentFilters = {
            event_type: document.getElementById('filterEventType').value,
            severity: document.getElementById('filterSeverity').value,
            search: document.getElementById('logSearchInput').value.trim(),
        };
        loadLogs(1);
    });
    document.getElementById('btnClearFilters')?.addEventListener('click', () => {
        document.getElementById('filterEventType').value = '';
        document.getElementById('filterSeverity').value = '';
        document.getElementById('logSearchInput').value = '';
        currentFilters = {};
        loadLogs(1);
    });
    document.getElementById('logSearchInput')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') document.getElementById('btnApplyFilters').click();
    });
    
    // Chain
    document.getElementById('btnRefreshChain')?.addEventListener('click', loadChain);
    
    // Verification
    document.getElementById('btnRunVerification')?.addEventListener('click', runVerification);
    
    // Tamper lab
    document.getElementById('btnTamperModify')?.addEventListener('click', async () => {
        const id = document.getElementById('tamperModifyId').value;
        const desc = document.getElementById('tamperModifyDesc').value;
        if (!id) { showToast('Enter an entry ID', 'warning'); return; }
        try {
            const data = await API.tamperModify(id, desc);
            showToast(data.message, 'warning');
        } catch (err) { showToast(err.message, 'error'); }
    });
    document.getElementById('btnTamperDelete')?.addEventListener('click', async () => {
        const id = document.getElementById('tamperDeleteId').value;
        if (!id) { showToast('Enter an entry ID', 'warning'); return; }
        try {
            const data = await API.tamperDelete(id);
            showToast(data.message, 'warning');
        } catch (err) { showToast(err.message, 'error'); }
    });
    document.getElementById('btnTamperReorder')?.addEventListener('click', async () => {
        const a = document.getElementById('tamperReorderA').value;
        const b = document.getElementById('tamperReorderB').value;
        if (!a || !b) { showToast('Enter both entry IDs', 'warning'); return; }
        try {
            const data = await API.tamperReorder(a, b);
            showToast(data.message, 'warning');
        } catch (err) { showToast(err.message, 'error'); }
    });
    document.getElementById('btnVerifyAfterTamper')?.addEventListener('click', () => { navigateTo('verify'); setTimeout(runVerification, 200); });
    document.getElementById('btnResetDB')?.addEventListener('click', async () => {
        try {
            showToast('Resetting database...', 'info');
            await API.reset();
            showToast('Database reset successfully!', 'success');
            loadDashboard();
        } catch (err) { showToast(err.message, 'error'); }
    });
    
    // Add log form
    document.getElementById('addLogForm')?.addEventListener('submit', handleAddLog);
    
    // Anchors
    document.getElementById('btnCreateAnchor')?.addEventListener('click', async () => {
        try {
            await API.createAnchor();
            showToast('Anchor created successfully', 'success');
            loadAnchors();
        } catch (err) { showToast(err.message, 'error'); }
    });
    
    // Export
    document.getElementById('btnExportJSON')?.addEventListener('click', async () => {
        try {
            showToast('Generating report...', 'info');
            const data = await API.exportReport();
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = `audit-report-${new Date().toISOString().slice(0,10)}.json`;
            a.click(); URL.revokeObjectURL(url);
            showToast('Report exported successfully', 'success');
        } catch (err) { showToast('Export failed: ' + err.message, 'error'); }
    });
    
    // Modal
    document.getElementById('modalClose')?.addEventListener('click', () => {
        document.getElementById('entryModal').classList.remove('open');
    });
    document.getElementById('entryModal')?.addEventListener('click', (e) => {
        if (e.target === document.getElementById('entryModal')) {
            document.getElementById('entryModal').classList.remove('open');
        }
    });
    
    // Load initial data
    loadFilterOptions();
    loadDashboard();
    updateAgentUI();
    
    // If agent is already running (auto-start), enable auto-refresh
    API.agentStatus().then(status => {
        if (status.running) {
            agentRefreshInterval = setInterval(() => {
                if (currentSection === 'dashboard') loadDashboard();
            }, 20000);
        }
    }).catch(() => {});
});
