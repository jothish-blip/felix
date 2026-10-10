// FELIX OPERATOR — Client-Side Application Controller
// Zero external dependencies; Pure vanilla ECMAScript 6+

(function() {
  'use strict';

  // --- STATE ---
  const state = {
    token: '',
    operatorID: 'operator',
    activeTab: 'dashboard',
    clients: [],
    assessments: [],
    selectedAssessmentId: null,
    findings: [],
    findingsSummary: { total: 0, approved: 0, rejected: 0, pending: 0 },
    activeStatusFilter: 'ALL',
    activeSevFilter: 'ALL',
    scanPollInterval: null,
  };

  // --- INITIALIZATION ---
  window.addEventListener('DOMContentLoaded', () => {
    initAuth();
    initNavigation();
    initCopyToken();
    loadDashboard();
  });

  function initAuth() {
    const params = new URLSearchParams(window.location.search);
    const urlToken = params.get('token');
    if (urlToken) {
      state.token = urlToken;
      sessionStorage.setItem('felix_operator_token', urlToken);
      // Clean query string from URL for cleaner display
      window.history.replaceState({}, document.title, window.location.pathname);
    } else {
      state.token = sessionStorage.getItem('felix_operator_token') || '';
    }

    // Fetch health to verify session & get operator identity
    fetchAPI('/api/v1/health')
      .then(data => {
        if (data && data.operator_id) {
          state.operatorID = data.operator_id;
          const userElem = document.getElementById('op-user-id');
          if (userElem) userElem.textContent = data.operator_id;
        }
      })
      .catch(err => {
        console.warn('Initial session check failed:', err);
      });
  }

  function initCopyToken() {
    const btn = document.getElementById('btn-copy-token');
    if (!btn) return;
    btn.addEventListener('click', () => {
      if (state.token) {
        navigator.clipboard.writeText(state.token).then(() => {
          showNotification('Operator token copied to clipboard', 'success');
        });
      } else {
        showNotification('No active operator token available', 'error');
      }
    });
  }

  function initNavigation() {
    document.querySelectorAll('.nav-tab').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.getAttribute('data-tab');
        switchTab(tab);
      });
    });

    // Finding review filter chips
    document.querySelectorAll('[data-filter-status]').forEach(chip => {
      chip.addEventListener('click', () => {
        document.querySelectorAll('[data-filter-status]').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        state.activeStatusFilter = chip.getAttribute('data-filter-status');
        renderFindings();
      });
    });

    document.querySelectorAll('[data-filter-sev]').forEach(chip => {
      chip.addEventListener('click', () => {
        document.querySelectorAll('[data-filter-sev]').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        state.activeSevFilter = chip.getAttribute('data-filter-sev');
        renderFindings();
      });
    });

    // Selectors
    const revSelect = document.getElementById('review-asm-selector');
    if (revSelect) {
      revSelect.addEventListener('change', (e) => {
        state.selectedAssessmentId = e.target.value;
        if (state.selectedAssessmentId) {
          loadFindingsForAssessment(state.selectedAssessmentId);
        } else {
          renderEmptyFindings();
        }
      });
    }

    const repSelect = document.getElementById('reports-asm-selector');
    if (repSelect) {
      repSelect.addEventListener('change', (e) => {
        const asmId = e.target.value;
        if (asmId) {
          loadReportsForAssessment(asmId);
        }
      });
    }

    const btnGenFromRev = document.getElementById('btn-generate-report-from-reviews');
    if (btnGenFromRev) {
      btnGenFromRev.addEventListener('click', () => {
        if (!state.selectedAssessmentId) {
          showNotification('Please select an assessment first', 'error');
          return;
        }
        openGenerateReportModal(state.selectedAssessmentId);
      });
    }

    const btnTriggerRepModal = document.getElementById('btn-trigger-report-modal');
    if (btnTriggerRepModal) {
      btnTriggerRepModal.addEventListener('click', () => {
        const asmId = document.getElementById('reports-asm-selector').value;
        if (!asmId) {
          showNotification('Please select an assessment first', 'error');
          return;
        }
        openGenerateReportModal(asmId);
      });
    }
  }

  // --- API HELPER ---
  async function fetchAPI(endpoint, options = {}) {
    const headers = options.headers || {};
    if (state.token) {
      headers['X-Felix-Operator-Token'] = state.token;
    }
    if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(options.body);
    }
    options.headers = headers;

    const res = await fetch(endpoint, options);
    if (res.status === 401) {
      showNotification('Unauthorized: invalid or missing operator token.', 'error');
      throw new Error('Unauthorized');
    }
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      const errMsg = (data && data.error) ? data.error : `HTTP error ${res.status}`;
      throw new Error(errMsg);
    }
    return data;
  }

  // --- NOTIFICATIONS ---
  function showNotification(msg, type = 'info') {
    const banner = document.getElementById('notification-banner');
    if (!banner) return;
    banner.className = `notification-banner ${type}`;
    banner.innerHTML = `<span>${escapeHTML(msg)}</span><button class="btn btn-sm btn-ghost" onclick="this.parentElement.classList.add('hidden')">&times;</button>`;
    banner.classList.remove('hidden');
    setTimeout(() => {
      banner.classList.add('hidden');
    }, 6000);
  }

  // --- TAB SWITCHING ---
  window.switchTab = function(tabName) {
    state.activeTab = tabName;
    document.querySelectorAll('.nav-tab').forEach(b => {
      b.classList.toggle('active', b.getAttribute('data-tab') === tabName);
    });
    document.querySelectorAll('.tab-pane').forEach(p => {
      p.classList.toggle('active', p.id === `tab-${tabName}`);
    });

    switch (tabName) {
      case 'dashboard': loadDashboard(); break;
      case 'clients': loadClients(); break;
      case 'assessments': loadAssessments(); break;
      case 'reviews': syncReviewSelectors(); break;
      case 'reports': syncReportsSelectors(); break;
      case 'audit': loadAuditEvents(); break;
    }
  };

  // --- DASHBOARD ---
  async function loadDashboard() {
    try {
      const [clientsRes, asmsRes, auditRes] = await Promise.all([
        fetchAPI('/api/v1/clients'),
        fetchAPI('/api/v1/assessments'),
        fetchAPI('/api/v1/audit?limit=6')
      ]);

      const clients = clientsRes.clients || [];
      const asms = asmsRes.assessments || [];
      const audits = auditRes.events || [];

      state.clients = clients;
      state.assessments = asms;

      document.getElementById('dash-clients-count').textContent = clients.length;
      document.getElementById('dash-assessments-count').textContent = asms.length;

      // Render recent assessments
      const asmList = document.getElementById('dash-assessments-list');
      if (asms.length === 0) {
        asmList.innerHTML = '<div class="list-empty">No assessments created yet. Click "+ New Assessment" above.</div>';
      } else {
        asmList.innerHTML = asms.slice(0, 5).map(a => `
          <div style="display:flex; justify-content:space-between; align-items:center; padding:0.6rem 0; border-bottom:1px solid var(--border-subtle);">
            <div>
              <span class="ref-badge">${escapeHTML(a.ref)}</span>
              <strong style="margin-left:0.5rem;">${escapeHTML(a.name)}</strong>
              <span class="badge ${getStatusBadgeClass(a.status)}" style="margin-left:0.5rem;">${escapeHTML(a.status)}</span>
            </div>
            <button class="btn btn-sm btn-secondary" onclick="viewAssessment('${escapeHTML(a.id)}')">View</button>
          </div>
        `).join('');
      }

      // Render recent audits
      const auditList = document.getElementById('dash-audit-list');
      if (audits.length === 0) {
        auditList.innerHTML = '<div class="list-empty">No operator actions logged yet.</div>';
      } else {
        auditList.innerHTML = audits.map(e => `
          <div style="display:flex; justify-content:space-between; align-items:center; padding:0.5rem 0; border-bottom:1px solid var(--border-subtle); font-size:0.84rem;">
            <div>
              <strong style="color:#38bdf8;">${escapeHTML(e.action_type)}</strong>
              <span style="color:var(--text-muted); margin-left:0.5rem;">${escapeHTML(e.entity_type)} ${escapeHTML(e.entity_id || '')}</span>
            </div>
            <span style="color:var(--text-dim); font-size:0.75rem;">${formatTime(e.created_at)}</span>
          </div>
        `).join('');
      }

    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    }
  }

  // --- CLIENTS ---
  async function loadClients() {
    try {
      const res = await fetchAPI('/api/v1/clients');
      state.clients = res.clients || [];
      const tbody = document.getElementById('clients-table-body');
      if (state.clients.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No clients registered yet.</td></tr>';
        return;
      }
      tbody.innerHTML = state.clients.map(c => `
        <tr>
          <td><strong>${escapeHTML(c.name)}</strong></td>
          <td>${escapeHTML(c.organization || '—')}</td>
          <td>${escapeHTML(c.contact_name || '—')}</td>
          <td>${escapeHTML(c.contact_email || '—')}</td>
          <td>${formatDate(c.created_at)}</td>
          <td>
            <button class="btn btn-sm btn-secondary" onclick="createAssessmentForClient('${escapeHTML(c.id)}')">+ Assessment</button>
          </td>
        </tr>
      `).join('');
    } catch (err) {
      showNotification(`Failed to load clients: ${err.message}`, 'error');
    }
  }

  window.handleCreateClientSubmit = async function(e) {
    e.preventDefault();
    const payload = {
      name: document.getElementById('client-name').value.trim(),
      organization: document.getElementById('client-org').value.trim(),
      contact_name: document.getElementById('client-contact-name').value.trim(),
      contact_email: document.getElementById('client-contact-email').value.trim(),
      notes: document.getElementById('client-notes').value.trim(),
    };

    try {
      await fetchAPI('/api/v1/clients', {
        method: 'POST',
        body: payload,
      });
      closeModal('modal-new-client');
      document.getElementById('form-new-client').reset();
      showNotification('Client registered successfully', 'success');
      loadClients();
    } catch (err) {
      showNotification(err.message, 'error');
    }
  };

  // --- ASSESSMENTS ---
  async function loadAssessments() {
    try {
      const res = await fetchAPI('/api/v1/assessments');
      state.assessments = res.assessments || [];
      const tbody = document.getElementById('assessments-table-body');
      if (state.assessments.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No assessments created yet.</td></tr>';
        return;
      }
      tbody.innerHTML = state.assessments.map(a => `
        <tr>
          <td><span class="ref-badge">${escapeHTML(a.ref)}</span></td>
          <td><strong>${escapeHTML(a.name)}</strong></td>
          <td>${escapeHTML(getClientName(a.client_id))}</td>
          <td><span class="badge badge-info">${escapeHTML(a.assessment_type)}</span></td>
          <td><span class="badge ${getStatusBadgeClass(a.status)}">${escapeHTML(a.status)}</span></td>
          <td>${a.target_count || 0} target(s)</td>
          <td>${formatDate(a.created_at)}</td>
          <td>
            <button class="btn btn-sm btn-secondary" onclick="viewAssessment('${escapeHTML(a.id)}')">Manage</button>
          </td>
        </tr>
      `).join('');
    } catch (err) {
      showNotification(`Failed to load assessments: ${err.message}`, 'error');
    }
  }

  window.handleCreateAssessmentSubmit = async function(e) {
    e.preventDefault();
    const payload = {
      client_id: document.getElementById('asm-client-id').value,
      name: document.getElementById('asm-name').value.trim(),
      assessment_type: document.getElementById('asm-type').value,
      scope_mode: document.getElementById('asm-scope-mode').value,
      description: document.getElementById('asm-desc').value.trim(),
    };

    try {
      const asm = await fetchAPI('/api/v1/assessments', {
        method: 'POST',
        body: payload,
      });
      closeModal('modal-new-assessment');
      document.getElementById('form-new-assessment').reset();
      showNotification(`Assessment ${asm.ref} created`, 'success');
      loadAssessments();
      viewAssessment(asm.id);
    } catch (err) {
      showNotification(err.message, 'error');
    }
  };

  window.viewAssessment = async function(id) {
    try {
      const data = await fetchAPI(`/api/v1/assessments/${id}`);
      const asm = data.assessment;
      const client = data.client;
      const revSummary = data.review_summary || { total: 0, approved: 0, rejected: 0, pending: 0 };

      state.selectedAssessmentId = asm.ID || asm.id;

      // Populate Detail Panel
      document.getElementById('det-asm-ref').textContent = asm.ref;
      document.getElementById('det-asm-name').textContent = asm.name;
      const statusBadge = document.getElementById('det-asm-status');
      statusBadge.textContent = asm.status;
      statusBadge.className = `badge ${getStatusBadgeClass(asm.status)}`;

      // Authorization info
      const authBox = document.getElementById('det-asm-auth-info');
      if (asm.authorization) {
        authBox.innerHTML = `
          <div><strong>Status:</strong> <span class="badge badge-success">${escapeHTML(asm.authorization.status)}</span></div>
          <div><strong>Authorized By:</strong> ${escapeHTML(asm.authorization.authorizing_party)}</div>
          <div><strong>Method:</strong> ${escapeHTML(asm.authorization.authorization_method)}</div>
          <div><strong>Valid Until:</strong> ${formatDate(asm.authorization.valid_until)}</div>
        `;
      } else {
        authBox.innerHTML = '<div class="text-warning">⚠️ No authorization recorded. Testing is prohibited until formal permission is recorded.</div>';
      }

      // Review progress
      document.getElementById('det-rev-approved').textContent = `${revSummary.approved} Approved`;
      document.getElementById('det-rev-pending').textContent = `${revSummary.pending} Pending`;
      document.getElementById('det-rev-rejected').textContent = `${revSummary.rejected} Rejected`;

      // Targets table
      const targetsBody = document.getElementById('det-asm-targets-body');
      const targets = asm.targets || [];
      if (targets.length === 0) {
        targetsBody.innerHTML = '<tr><td colspan="4" class="text-muted">No targets added yet. Click "+ Add Target" above.</td></tr>';
      } else {
        targetsBody.innerHTML = targets.map(t => `
          <tr>
            <td><code>${escapeHTML(t.target_url)}</code></td>
            <td><span class="badge badge-info">${escapeHTML(t.target_type)}</span></td>
            <td><span class="badge badge-success">${escapeHTML(t.scope_status)}</span></td>
            <td>${escapeHTML(t.label || '—')}</td>
          </tr>
        `).join('');
      }

      // Buttons wiring
      document.getElementById('btn-asm-add-target').onclick = () => openAddTargetModal(asm.id);
      document.getElementById('btn-asm-authorize').onclick = () => openAuthorizeModal(asm.id);
      document.getElementById('btn-asm-scan').onclick = () => triggerScan(asm.id);
      document.getElementById('btn-goto-review').onclick = () => {
        switchTab('reviews');
        const sel = document.getElementById('review-asm-selector');
        if (sel) {
          sel.value = asm.id;
          loadFindingsForAssessment(asm.id);
        }
      };

      // Check if scan is running
      checkScanRunning(asm.id);

      // Show panel
      document.getElementById('assessment-detail-panel').classList.remove('hidden');
      document.getElementById('assessment-detail-panel').scrollIntoView({ behavior: 'smooth' });

    } catch (err) {
      showNotification(`Failed to load assessment detail: ${err.message}`, 'error');
    }
  };

  window.closeAssessmentDetail = function() {
    document.getElementById('assessment-detail-panel').classList.add('hidden');
    if (state.scanPollInterval) {
      clearInterval(state.scanPollInterval);
      state.scanPollInterval = null;
    }
  };

  // --- SCAN RUNNING & POLLING ---
  async function triggerScan(asmId) {
    try {
      const res = await fetchAPI(`/api/v1/assessments/${asmId}/scan`, {
        method: 'POST',
        body: {},
      });
      showNotification(res.message || 'Scan started in background', 'success');
      startScanPolling(asmId);
    } catch (err) {
      showNotification(err.message, 'error');
    }
  }

  async function checkScanRunning(asmId) {
    try {
      const status = await fetchAPI(`/api/v1/assessments/${asmId}/scan/status`);
      if (status && (status.state === 'RUNNING' || status.state === 'QUEUED')) {
        startScanPolling(asmId);
      }
    } catch (_) {
      // No active scan
    }
  }

  function startScanPolling(asmId) {
    const bar = document.getElementById('scan-running-bar');
    if (bar) bar.classList.remove('hidden');

    const cancelBtn = document.getElementById('btn-scan-cancel');
    if (cancelBtn) {
      cancelBtn.onclick = () => cancelScan(asmId);
    }

    if (state.scanPollInterval) clearInterval(state.scanPollInterval);

    state.scanPollInterval = setInterval(async () => {
      try {
        const s = await fetchAPI(`/api/v1/assessments/${asmId}/scan/status`);
        if (!s) return;

        document.getElementById('scan-state-label').textContent = s.state;
        document.getElementById('scan-progress-msg').textContent = s.progress_message || 'Running assessment pipeline...';

        if (s.state === 'COMPLETED' || s.state === 'FAILED' || s.state === 'CANCELLED') {
          clearInterval(state.scanPollInterval);
          state.scanPollInterval = null;
          bar.classList.add('hidden');
          showNotification(`Scan finished with state: ${s.state}`, s.state === 'COMPLETED' ? 'success' : 'error');
          viewAssessment(asmId);
        }
      } catch (err) {
        clearInterval(state.scanPollInterval);
        state.scanPollInterval = null;
        bar.classList.add('hidden');
      }
    }, 2000);
  }

  async function cancelScan(asmId) {
    try {
      await fetchAPI(`/api/v1/assessments/${asmId}/scan/cancel`, { method: 'POST' });
      showNotification('Scan cancellation requested', 'info');
    } catch (err) {
      showNotification(err.message, 'error');
    }
  }

  // --- TARGETS & AUTHORIZATION ---
  function openAddTargetModal(asmId) {
    showModal('modal-add-target');
  }

  window.handleAddTargetSubmit = async function(e) {
    e.preventDefault();
    if (!state.selectedAssessmentId) return;

    const payload = {
      target_url: document.getElementById('target-url').value.trim(),
      target_type: document.getElementById('target-type').value,
      label: document.getElementById('target-label').value.trim(),
    };

    try {
      await fetchAPI(`/api/v1/assessments/${state.selectedAssessmentId}/targets`, {
        method: 'POST',
        body: payload,
      });
      closeModal('modal-add-target');
      document.getElementById('form-add-target').reset();
      showNotification('Target added to assessment scope', 'success');
      viewAssessment(state.selectedAssessmentId);
    } catch (err) {
      showNotification(err.message, 'error');
    }
  };

  function openAuthorizeModal(asmId) {
    showModal('modal-authorize');
  }

  window.handleAuthorizeSubmit = async function(e) {
    e.preventDefault();
    if (!state.selectedAssessmentId) return;

    const payload = {
      authorizing_party: document.getElementById('auth-party').value.trim(),
      authorization_method: document.getElementById('auth-method').value,
      valid_days: parseInt(document.getElementById('auth-days').value, 10) || 30,
      scope_doc_ref: document.getElementById('auth-doc-ref').value.trim(),
      internal_notes: document.getElementById('auth-notes').value.trim(),
    };

    try {
      await fetchAPI(`/api/v1/assessments/${state.selectedAssessmentId}/authorize`, {
        method: 'POST',
        body: payload,
      });
      closeModal('modal-authorize');
      document.getElementById('form-authorize').reset();
      showNotification('Formal assessment authorization recorded', 'success');
      viewAssessment(state.selectedAssessmentId);
    } catch (err) {
      showNotification(err.message, 'error');
    }
  };

  // --- FINDINGS & REVIEW WORKBENCH ---
  function syncReviewSelectors() {
    const sel = document.getElementById('review-asm-selector');
    if (!sel) return;
    const currentVal = sel.value;
    sel.innerHTML = '<option value="">Select Assessment...</option>' +
      state.assessments.map(a => `<option value="${escapeHTML(a.id)}">${escapeHTML(a.ref)} — ${escapeHTML(a.name)}</option>`).join('');
    if (state.selectedAssessmentId) {
      sel.value = state.selectedAssessmentId;
      loadFindingsForAssessment(state.selectedAssessmentId);
    } else if (currentVal) {
      sel.value = currentVal;
    }
  }

  async function loadFindingsForAssessment(asmId) {
    try {
      const res = await fetchAPI(`/api/v1/assessments/${asmId}/findings`);
      state.findings = res.findings || [];
      state.findingsSummary = res.summary || { total: 0, approved: 0, rejected: 0, pending: 0 };
      updateReviewSummaryBar();
      renderFindings();
    } catch (err) {
      showNotification(`Failed to load findings: ${err.message}`, 'error');
    }
  }

  function updateReviewSummaryBar() {
    const s = state.findingsSummary;
    document.getElementById('rev-bar-total').textContent = s.total;
    document.getElementById('rev-bar-approved').textContent = s.approved;
    document.getElementById('rev-bar-pending').textContent = s.pending;
    document.getElementById('rev-bar-rejected').textContent = s.rejected;
  }

  function renderEmptyFindings() {
    const container = document.getElementById('findings-container');
    container.innerHTML = '<div class="card p-4 text-center text-muted">Please select an assessment to review findings.</div>';
    state.findings = [];
    state.findingsSummary = { total: 0, approved: 0, rejected: 0, pending: 0 };
    updateReviewSummaryBar();
  }

  function renderFindings() {
    const container = document.getElementById('findings-container');
    if (!container) return;

    let items = state.findings;

    // Filter by review status
    if (state.activeStatusFilter !== 'ALL') {
      items = items.filter(f => f.review_status === state.activeStatusFilter);
    }

    // Filter by severity
    if (state.activeSevFilter !== 'ALL') {
      items = items.filter(f => (f.severity || '').toUpperCase() === state.activeSevFilter);
    }

    if (items.length === 0) {
      container.innerHTML = '<div class="card p-4 text-center text-muted">No findings match the selected filters.</div>';
      return;
    }

    container.innerHTML = items.map(f => {
      const sevClass = getSeverityBadgeClass(f.severity);
      const revClass = getReviewBadgeClass(f.review_status);
      const obsText = (f.evidence && f.evidence.observation) || f.evidence_details?.observation || 'No observation details';

      return `
        <div class="finding-card">
          <div class="finding-card-header">
            <div class="finding-title-group">
              <span class="badge ${sevClass}">${escapeHTML(f.severity)}</span>
              <span class="finding-title">${escapeHTML(f.title)}</span>
            </div>
            <div class="finding-review-badge">
              <span class="badge ${revClass}">${escapeHTML(f.review_status)}</span>
              <button class="btn btn-sm btn-primary" onclick="openReviewModal('${escapeHTML(f.id)}')">Review &rarr;</button>
            </div>
          </div>
          <div class="finding-meta-row">
            <span>Category: <code>${escapeHTML(f.category)}</code></span>
            <span>Target: <code>${escapeHTML(f.target_url || f.endpoint || '—')}</code></span>
            <span>Verification: <strong>${escapeHTML(f.verification_status || 'DETECTED')}</strong></span>
            <span>Confidence: <strong>${escapeHTML(f.confidence || 'MEDIUM')}</strong></span>
          </div>
          ${f.review && f.review.notes ? `
            <div class="finding-notes-banner">
              <strong>Operator Notes:</strong> ${escapeHTML(f.review.notes)}
              <span style="font-size:0.75rem; color:var(--text-dim); margin-left:0.5rem;">(by ${escapeHTML(f.review.reviewed_by)})</span>
            </div>
          ` : ''}
          <div class="evidence-box">${escapeHTML(obsText)}</div>
        </div>
      `;
    }).join('');
  }

  window.openReviewModal = function(findingId) {
    const f = state.findings.find(item => item.id === findingId || item.original_finding_id === findingId);
    if (!f) return;

    document.getElementById('rev-finding-id').value = f.id;
    document.getElementById('rev-asm-id').value = state.selectedAssessmentId;
    document.getElementById('rev-modal-title').textContent = f.title;
    document.getElementById('rev-modal-sev').textContent = f.severity;
    document.getElementById('rev-modal-sev').className = `badge ${getSeverityBadgeClass(f.severity)}`;
    document.getElementById('rev-modal-target').textContent = f.target_url || f.endpoint || '—';
    document.getElementById('rev-modal-ver').textContent = f.verification_status || 'DETECTED';
    document.getElementById('rev-modal-conf').textContent = f.confidence || 'MEDIUM';

    // Pre-fill radio
    const radios = document.getElementsByName('review_status');
    const curStatus = f.review_status || 'PENDING';
    for (const r of radios) {
      r.checked = (r.value === curStatus);
    }

    // Pre-fill notes
    document.getElementById('rev-notes').value = (f.review && f.review.notes) ? f.review.notes : '';

    // Evidence
    const obsText = (f.evidence && f.evidence.observation) || f.evidence_details?.observation || 'No evidence recorded';
    document.getElementById('rev-modal-evidence').textContent = obsText;

    showModal('modal-review-finding');
  };

  window.handleReviewFindingSubmit = async function(e) {
    e.preventDefault();
    const asmId = document.getElementById('rev-asm-id').value;
    const findingId = document.getElementById('rev-finding-id').value;
    const radios = document.getElementsByName('review_status');
    let chosenStatus = 'APPROVED_FOR_REPORT';
    for (const r of radios) {
      if (r.checked) chosenStatus = r.value;
    }
    const notes = document.getElementById('rev-notes').value.trim();

    try {
      await fetchAPI(`/api/v1/assessments/${asmId}/findings/${findingId}/review`, {
        method: 'POST',
        body: {
          status: chosenStatus,
          notes: notes,
        },
      });
      closeModal('modal-review-finding');
      showNotification(`Finding review saved: ${chosenStatus}`, 'success');
      loadFindingsForAssessment(asmId);
    } catch (err) {
      showNotification(err.message, 'error');
    }
  };

  // --- REPORTS & DELIVERY ---
  function syncReportsSelectors() {
    const sel = document.getElementById('reports-asm-selector');
    if (!sel) return;
    const currentVal = sel.value;
    sel.innerHTML = '<option value="">Select Assessment...</option>' +
      state.assessments.map(a => `<option value="${escapeHTML(a.id)}">${escapeHTML(a.ref)} — ${escapeHTML(a.name)}</option>`).join('');
    if (state.selectedAssessmentId) {
      sel.value = state.selectedAssessmentId;
      loadReportsForAssessment(state.selectedAssessmentId);
    } else if (currentVal) {
      sel.value = currentVal;
    }
  }

  async function loadReportsForAssessment(asmId) {
    try {
      const [repsRes, delivRes] = await Promise.all([
        fetchAPI(`/api/v1/assessments/${asmId}/reports`),
        fetchAPI(`/api/v1/assessments/${asmId}/deliveries`)
      ]);

      const reports = repsRes.reports || [];
      const deliveries = delivRes.deliveries || [];

      // Reports table
      const repBody = document.getElementById('reports-table-body');
      if (reports.length === 0) {
        repBody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No commercial reports generated yet. Click "+ Generate Report" above.</td></tr>';
      } else {
        repBody.innerHTML = reports.map(r => `
          <tr>
            <td><span class="badge badge-info">${escapeHTML(r.format)}</span></td>
            <td>${formatTime(r.created_at)}</td>
            <td><span class="badge badge-success">${escapeHTML(r.status)}</span></td>
            <td>
              <a href="/api/v1/assessments/${asmId}/reports/${escapeHTML(r.id)}/${r.format.toLowerCase()}?token=${state.token}" target="_blank" class="btn btn-sm btn-secondary">Open</a>
              <button class="btn btn-sm btn-primary" onclick="openRecordDeliveryModal('${escapeHTML(asmId)}', '${escapeHTML(r.id)}')">Record Delivery</button>
            </td>
          </tr>
        `).join('');
      }

      // Deliveries table
      const delivBody = document.getElementById('deliveries-table-body');
      if (deliveries.length === 0) {
        delivBody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No delivery records logged yet.</td></tr>';
      } else {
        delivBody.innerHTML = deliveries.map(d => `
          <tr>
            <td><strong>${escapeHTML(d.recipient_name)}</strong> ${d.recipient_email ? `<br><small class="text-muted">${escapeHTML(d.recipient_email)}</small>` : ''}</td>
            <td><span class="badge badge-info">${escapeHTML(d.delivery_method)}</span></td>
            <td><span class="badge ${d.delivery_status === 'DELIVERY_CONFIRMED' ? 'badge-success' : 'badge-warning'}">${escapeHTML(d.delivery_status)}</span></td>
            <td>${formatTime(d.delivered_at || d.dispatched_at)}</td>
            <td>${escapeHTML(d.operator_id)}</td>
          </tr>
        `).join('');
      }

    } catch (err) {
      showNotification(`Failed to load reports: ${err.message}`, 'error');
    }
  }

  function openGenerateReportModal(asmId) {
    const asm = state.assessments.find(a => a.id === asmId);
    document.getElementById('gen-rep-asm-id').value = asmId;
    document.getElementById('gen-rep-asm-name').value = asm ? `${asm.ref} — ${asm.name}` : asmId;
    document.getElementById('gen-rep-draft').checked = false;
    showModal('modal-generate-report');
  }

  window.handleGenerateReportSubmit = async function(e) {
    e.preventDefault();
    const asmId = document.getElementById('gen-rep-asm-id').value;
    const allowDraft = document.getElementById('gen-rep-draft').checked;

    try {
      const res = await fetchAPI(`/api/v1/assessments/${asmId}/reports/generate`, {
        method: 'POST',
        body: { allow_draft: allowDraft },
      });
      closeModal('modal-generate-report');
      showNotification(`Commercial report generated (${res.is_draft ? 'DRAFT' : 'FINAL'})`, 'success');
      loadReportsForAssessment(asmId);
    } catch (err) {
      showNotification(err.message, 'error');
    }
  };

  window.openRecordDeliveryModal = function(asmId, reportId) {
    document.getElementById('deliv-asm-id').value = asmId;
    document.getElementById('deliv-report-id').value = reportId;
    document.getElementById('form-record-delivery').reset();
    document.getElementById('deliv-confirmed').checked = true;
    showModal('modal-record-delivery');
  };

  window.handleRecordDeliverySubmit = async function(e) {
    e.preventDefault();
    const asmId = document.getElementById('deliv-asm-id').value;
    const reportId = document.getElementById('deliv-report-id').value;
    const payload = {
      recipient_name: document.getElementById('deliv-recipient-name').value.trim(),
      recipient_email: document.getElementById('deliv-recipient-email').value.trim(),
      delivery_method: document.getElementById('deliv-method').value,
      confirmed: document.getElementById('deliv-confirmed').checked,
      notes: document.getElementById('deliv-notes').value.trim(),
    };

    try {
      await fetchAPI(`/api/v1/assessments/${asmId}/reports/${reportId}/deliver`, {
        method: 'POST',
        body: payload,
      });
      closeModal('modal-record-delivery');
      showNotification('Report delivery logged successfully', 'success');
      loadReportsForAssessment(asmId);
    } catch (err) {
      showNotification(err.message, 'error');
    }
  };

  // --- AUDIT TRAIL ---
  window.loadAuditEvents = async function() {
    try {
      const res = await fetchAPI('/api/v1/audit?limit=100');
      const events = res.events || [];
      const tbody = document.getElementById('audit-table-body');
      if (events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No audit events recorded yet.</td></tr>';
        return;
      }
      tbody.innerHTML = events.map(ev => `
        <tr>
          <td><code style="font-size:0.78rem;">${formatTime(ev.created_at)}</code></td>
          <td>${escapeHTML(ev.operator_id)}</td>
          <td><strong style="color:#38bdf8;">${escapeHTML(ev.action_type)}</strong></td>
          <td>${escapeHTML(ev.entity_type)}</td>
          <td><code>${escapeHTML(ev.entity_id || '—')}</code></td>
          <td style="max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:0.78rem; color:var(--text-muted);">${escapeHTML(ev.details_json || '—')}</td>
        </tr>
      `).join('');
    } catch (err) {
      showNotification(`Failed to load audit events: ${err.message}`, 'error');
    }
  };

  // --- MODAL UTILITIES ---
  window.showModal = function(id) {
    const modal = document.getElementById(id);
    if (modal) modal.classList.remove('hidden');
  };

  window.closeModal = function(id) {
    const modal = document.getElementById(id);
    if (modal) modal.classList.add('hidden');
  };

  // --- HELPERS ---
  function getClientName(id) {
    const c = state.clients.find(item => item.id === id);
    return c ? c.name : id;
  }

  function getStatusBadgeClass(status) {
    switch (status) {
      case 'READY': return 'badge-info';
      case 'RUNNING': return 'badge-warning';
      case 'COMPLETED': return 'badge-success';
      case 'FAILED': return 'badge-danger';
      case 'CANCELLED': return 'badge-danger';
      default: return 'badge-info';
    }
  }

  function getSeverityBadgeClass(sev) {
    switch ((sev || '').toUpperCase()) {
      case 'CRITICAL': return 'badge-crit';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-med';
      case 'LOW': return 'badge-low';
      default: return 'badge-info';
    }
  }

  function getReviewBadgeClass(status) {
    switch (status) {
      case 'APPROVED_FOR_REPORT': return 'badge-success';
      case 'REJECTED': return 'badge-danger';
      case 'PENDING': return 'badge-warning';
      default: return 'badge-warning';
    }
  }

  function formatDate(dStr) {
    if (!dStr) return '—';
    try {
      const d = new Date(dStr);
      return d.toLocaleDateString();
    } catch {
      return dStr;
    }
  }

  function formatTime(dStr) {
    if (!dStr) return '—';
    try {
      const d = new Date(dStr);
      return d.toISOString().replace('T', ' ').slice(0, 19) + 'Z';
    } catch {
      return dStr;
    }
  }

  function escapeHTML(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

})();
