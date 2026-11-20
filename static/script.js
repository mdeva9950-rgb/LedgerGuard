/* =========================================================
   LEDGERGUARD DASHBOARD — STABLE FRONTEND
   Uses only the Flask routes already present in the supplied app.py.
   No backend, database, or encryption changes are required.
   ========================================================= */

const state = {
    dashboardUnlocked: false,
    activeView: "overview",
    managerAction: "login",
    selectedRequestId: null,
    pollingTimer: null,
    handlingSessionExpiry: false,
    requestSubmitting: false,
    loginSubmitting: false,
    activeDecisions: new Set(),
    auditLogs: []
};

const pageCopy = {
    overview: {
        title: "Overview",
        eyebrow: "SECURITY AT A GLANCE",
        subtitle: "A focused view of your vendor banking security."
    },
    requests: {
        title: "Bank requests",
        eyebrow: "VENDOR WORKFLOW",
        subtitle: "Submit, review and decide on vendor bank detail changes."
    },
    threats: {
        title: "Threat monitor",
        eyebrow: "SECURITY INTELLIGENCE",
        subtitle: "Review recorded suspicious activity and source IPs."
    },
    activity: {
        title: "Activity & alerts",
        eyebrow: "EVENT VISIBILITY",
        subtitle: "Review the latest security events and generated alerts."
    },
    reports: {
        title: "Audit & reports",
        eyebrow: "TRACEABILITY",
        subtitle: "Search recorded events and export a security report."
    }
};

const $ = id => document.getElementById(id);

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    }[char]));
}

function setText(id, value) {
    const node = $(id);
    if (node) node.textContent = value == null ? "" : String(value);
}

function setMessage(id, message, className = "inline-error") {
    const node = $(id);
    if (!node) return;
    node.textContent = message || "";
    node.className = className;
}

function formatDate(value) {
    return value ? String(value) : "—";
}

function maskAccount(value) {
    const raw = String(value ?? "").trim();
    if (!raw || raw === "DECRYPTION ERROR") return "Not available";
    return `•••• ${raw.slice(-4)}`;
}

function showResult(kind, heading, message, requestId = null) {
    const result = $("result");
    if (!result) return;
    const requestLine = requestId == null
        ? ""
        : `<small>Request #${escapeHTML(requestId)}</small>`;
    result.innerHTML = `
        <div class="result-card ${kind === "success" ? "success-result" : "error-result"}" role="status">
            <strong>${escapeHTML(heading)}</strong>
            <p>${escapeHTML(message)}</p>
            ${requestLine}
        </div>`;
}

function setAuthButton() {
    const button = $("ledgerGuardLogout");
    if (!button) return;
    button.textContent = state.dashboardUnlocked ? "Log out" : "Manager sign-in";
    button.setAttribute("aria-label", state.dashboardUnlocked ? "Log out manager" : "Open manager sign-in");
}

function setProtectedPlaceholder(id, message) {
    const node = $(id);
    if (node) node.innerHTML = `<p class="empty-state">${escapeHTML(message)}</p>`;
}

function clearProtectedViews() {
    const placeholders = {
        requestList: "Sign in to view bank requests.",
        alertList: "Sign in to view security alerts.",
        overviewAlerts: "Sign in to view the latest alerts.",
        timelineList: "Sign in to view the activity timeline.",
        logList: "Sign in to view audit logs.",
        threatIPList: "Sign in to view threat IPs.",
        attackChart: "Sign in to view attack activity."
    };

    Object.entries(placeholders).forEach(([id, message]) => setProtectedPlaceholder(id, message));

    ["totalCount", "pendingCount", "approvedCount", "blockedCount", "rejectedCount",
        "monitorAttacks", "monitorAlerts", "monitorBlocked", "healthScore", "pendingNavCount"]
        .forEach(id => setText(id, "—"));

    setText("healthStatus", "LOCKED");
    setText("healthStatusMessage", "Manager sign-in is required to view security posture.");
    setText("healthUpdated", "Waiting for sign-in");
    setText("monitorStatus", "LOCKED");
    setText("monitorUpdated", "Waiting for sign-in");
    setMessage("monitorError", "");
    setMessage("healthError", "");
    setMessage("attackChartError", "");
    setMessage("threatIPError", "");
    setMessage("timelineError", "");
    setMessage("alertError", "");
    setMessage("logError", "");

    state.auditLogs = [];
    state.activeDecisions.clear();
    setAuthButton();
}

function handleSessionExpiry() {
    if (state.handlingSessionExpiry || !state.dashboardUnlocked) return;
    state.handlingSessionExpiry = true;
    state.dashboardUnlocked = false;
    stopPolling();
    clearProtectedViews();
    showModal("login");
    showLoginError("Your manager session has expired. Please sign in again.");
    state.handlingSessionExpiry = false;
}

/*
 * Parse JSON safely and make API errors readable. All Flask API calls
 * stay on the same origin so the session cookie is included.
 */
async function fetchJSON(url, options = {}) {
    let response;
    try {
        response = await fetch(url, {
            credentials: "same-origin",
            ...options,
            headers: {
                Accept: "application/json",
                ...(options.headers || {})
            }
        });
    } catch (networkError) {
        const error = new Error("Cannot reach LedgerGuard. Check that Flask is running and try again.");
        error.cause = networkError;
        throw error;
    }

    const raw = await response.text();
    let data = {};
    if (raw) {
        try {
            data = JSON.parse(raw);
        } catch (_) {
            data = { error: raw.slice(0, 300) };
        }
    }

    if (!response.ok) {
        let message = data.error || data.message || data.reason;
        if (!message || typeof message !== "string") {
            message = `The server returned HTTP ${response.status}.`;
        }
        const error = new Error(message);
        error.status = response.status;
        error.data = data;

        if (
            response.status === 401 &&
            !["/api/manager-login", "/api/session-status", "/api/manager-logout"].includes(url)
        ) {
            handleSessionExpiry();
        }
        throw error;
    }

    return data;
}

// =========================================================
// NAVIGATION
// =========================================================

function switchView(viewName) {
    if (!pageCopy[viewName]) return;
    state.activeView = viewName;

    document.querySelectorAll(".nav-link[data-view]").forEach(button => {
        const active = button.dataset.view === viewName;
        button.classList.toggle("active", active);
        if (active) button.setAttribute("aria-current", "page");
        else button.removeAttribute("aria-current");
    });

    document.querySelectorAll(".view-panel").forEach(panel => {
        const active = panel.id === `view-${viewName}`;
        panel.classList.toggle("active", active);
        panel.hidden = !active;
    });

    const copy = pageCopy[viewName];
    setText("pageTitle", copy.title);
    setText("pageEyebrow", copy.eyebrow);
    setText("pageSubtitle", copy.subtitle);
    setText("breadcrumbCurrent", copy.title.toUpperCase());

    if (state.dashboardUnlocked) loadViewData(viewName);
}

function updatePageDate() {
    const node = $("pageDate");
    if (!node) return;
    node.textContent = new Intl.DateTimeFormat(undefined, {
        weekday: "short", day: "numeric", month: "short", year: "numeric"
    }).format(new Date());
}

document.querySelectorAll(".nav-link[data-view]").forEach(button => {
    button.addEventListener("click", () => switchView(button.dataset.view));
});

document.querySelectorAll("[data-open-view]").forEach(button => {
    button.addEventListener("click", () => switchView(button.dataset.openView));
});

// =========================================================
// MANAGER AUTHENTICATION AND SESSION
// =========================================================

function showModal(action = "login", requestId = null) {
    state.managerAction = action;
    state.selectedRequestId = requestId == null ? null : Number(requestId);

    const modal = $("managerModal");
    const form = $("managerLoginForm");
    if (!modal || !form) return;

    form.reset();
    setMessage("managerMessage", "", "");
    setText("managerModalTitle", action === "approve"
        ? `Sign in to approve request #${state.selectedRequestId}`
        : action === "reject"
            ? `Sign in to reject request #${state.selectedRequestId}`
            : action === "export" ? "Sign in to export report" : "Manager authentication");
    modal.classList.remove("hidden");
    document.body.classList.add("modal-open");
    if ($("managerUsername")) $("managerUsername").focus();
}

function hideModal() {
    const modal = $("managerModal");
    if (modal) modal.classList.add("hidden");
    document.body.classList.remove("modal-open");
    if ($("managerLoginForm")) $("managerLoginForm").reset();
    setMessage("managerMessage", "", "");
    state.managerAction = "login";
    state.selectedRequestId = null;
}

function showLoginError(message) {
    const target = $("managerMessage");
    if (!target) return;
    target.innerHTML = `<div class="login-error" role="alert">${escapeHTML(message)}</div>`;
}

$("cancelManagerLogin").addEventListener("click", hideModal);
$("managerModal").addEventListener("click", event => {
    if (event.target === $("managerModal")) hideModal();
});

document.addEventListener("keydown", event => {
    const modal = $("managerModal");
    if (event.key === "Escape" && modal && !modal.classList.contains("hidden")) hideModal();
});

$("managerLoginForm").addEventListener("submit", async event => {
    event.preventDefault();
    if (state.loginSubmitting) return;

    const actionAfterLogin = state.managerAction;
    const requestIdAfterLogin = state.selectedRequestId;
    const button = $("managerLoginButton");
    const username = $("managerUsername").value.trim();
    const password = $("managerPassword").value;

    state.loginSubmitting = true;
    button.disabled = true;
    button.textContent = "Signing in…";
    setMessage("managerMessage", "", "");

    try {
        await fetchJSON("/api/manager-login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });

        state.dashboardUnlocked = true;
        setAuthButton();
        hideModal();

        if (actionAfterLogin === "approve" || actionAfterLogin === "reject") {
            await performRequestDecision(requestIdAfterLogin, actionAfterLogin);
        } else if (actionAfterLogin === "export") {
            setText("exportReportStatus", "Your CSV report is being prepared.");
            window.location.assign("/api/export-report");
        } else {
            await refreshDashboard();
        }

        startPolling();
    } catch (error) {
        showLoginError(error.message);
    } finally {
        state.loginSubmitting = false;
        button.disabled = false;
        button.innerHTML = "Sign in securely <span>→</span>";
    }
});

$("ledgerGuardLogout").addEventListener("click", async () => {
    if (!state.dashboardUnlocked) {
        showModal("login");
        return;
    }

    const button = $("ledgerGuardLogout");
    button.disabled = true;
    try {
        await fetchJSON("/api/manager-logout", { method: "POST" });
        state.dashboardUnlocked = false;
        stopPolling();
        clearProtectedViews();
        setAuthButton();
        switchView("overview");
        showModal("login");
    } catch (error) {
        showResult("error", "Logout failed", error.message);
    } finally {
        button.disabled = false;
    }
});

// =========================================================
// REQUEST SUBMISSION
// =========================================================

$("requestForm").addEventListener("submit", async event => {
    event.preventDefault();
    if (state.requestSubmitting) return;

    const vendorName = $("vendor").value.trim();
    const bankAccount = $("account").value.trim();
    if (!vendorName || !bankAccount) {
        showResult("error", "Missing information", "Enter both a vendor name and demo bank account number.");
        return;
    }
    if (vendorName.length > 200 || bankAccount.length > 100) {
        showResult("error", "Input too long", "Vendor names are limited to 200 characters and account values to 100 characters.");
        return;
    }

    const button = $("submitButton");
    state.requestSubmitting = true;
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    button.textContent = "Submitting…";
    $("result").innerHTML = "";

    try {
        const data = await fetchJSON("/api/request-change", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ vendor_name: vendorName, bank_account: bankAccount })
        });

        if (data.status !== "PENDING" || data.request_id == null) {
            throw new Error(data.error || "The server did not confirm that the request was saved.");
        }

        showResult("success", "Request submitted successfully", data.reason || "The request was recorded and is awaiting manager review.", data.request_id);
        $("requestForm").reset();

        if (state.dashboardUnlocked) {
            await Promise.allSettled([loadRequests(), loadSecurityStats(), loadAlerts()]);
        }
    } catch (error) {
        showResult("error", "Request not submitted", error.message);
    } finally {
        state.requestSubmitting = false;
        button.disabled = false;
        button.removeAttribute("aria-busy");
        button.innerHTML = "Submit for review <span>→</span>";
    }
});

// =========================================================
// REQUEST QUEUE AND APPROVAL / REJECTION
// =========================================================

async function loadRequests() {
    const container = $("requestList");
    try {
        const requests = await fetchJSON("/api/requests");
        if (!Array.isArray(requests)) throw new Error("The requests endpoint returned an unexpected response.");

        const pending = requests.filter(item => String(item.status).toUpperCase() === "PENDING").length;
        setText("pendingNavCount", pending);

        if (requests.length === 0) {
            container.innerHTML = `<div class="empty-block"><span>✓</span><strong>No requests yet</strong><p>New vendor bank changes will appear here.</p></div>`;
            return;
        }

        container.innerHTML = requests.map(item => {
            const id = Number(item.id);
            const status = String(item.status || "UNKNOWN").toUpperCase();
            const canDecide = status === "PENDING" && Number.isSafeInteger(id) && id > 0;
            const busy = state.activeDecisions.has(id);
            const actions = canDecide ? `
                <div class="request-action-group">
                    <button type="button" class="decision-button approve" data-decision="approve" data-id="${id}" ${busy ? "disabled" : ""}>${busy ? "Working…" : "Approve"}</button>
                    <button type="button" class="decision-button reject" data-decision="reject" data-id="${id}" ${busy ? "disabled" : ""}>Reject</button>
                </div>` : "";

            return `
                <article class="request-row" data-request-id="${Number.isSafeInteger(id) ? id : ""}">
                    <div class="request-row-main">
                        <span class="request-id">REQUEST #${Number.isSafeInteger(id) ? id : "—"}</span>
                        <h3>${escapeHTML(item.vendor_name || "Unnamed vendor")}</h3>
                        <p class="account-mask">Account ${escapeHTML(maskAccount(item.bank_account))}</p>
                        <small>${escapeHTML(formatDate(item.created_at))}</small>
                    </div>
                    <div class="request-row-side">
                        <span class="status-badge ${escapeHTML(status.toLowerCase())}">${escapeHTML(status)}</span>
                        ${actions}
                    </div>
                </article>`;
        }).join("");
    } catch (error) {
        container.innerHTML = `<p class="inline-error">Could not load requests: ${escapeHTML(error.message)}</p>`;
    }
}

$("requestList").addEventListener("click", event => {
    const button = event.target.closest("button[data-decision]");
    if (!button || button.disabled) return;

    const action = button.dataset.decision;
    const id = Number(button.dataset.id);
    if (!["approve", "reject"].includes(action) || !Number.isSafeInteger(id) || id <= 0) return;

    // Require the manager to re-enter credentials for every decision,
    // even when a dashboard session is already active.
    showModal(action, id);
});

async function refreshAfterDecision() {
    await Promise.allSettled([
        loadRequests(),
        loadSecurityStats(),
        loadAlerts(),
        loadAuditLogs()
    ]);
}

async function performRequestDecision(requestId, action) {
    const id = Number(requestId);
    if (!Number.isSafeInteger(id) || id <= 0 || !["approve", "reject"].includes(action)) {
        showResult("error", "Invalid request", "The selected request or action is not valid.");
        return;
    }
    if (!state.dashboardUnlocked) {
        showModal(action, id);
        return;
    }
    if (state.activeDecisions.has(id)) return;

    state.activeDecisions.add(id);
    const row = document.querySelector(`.request-row[data-request-id="${id}"]`);
    if (row) row.querySelectorAll(".decision-button").forEach(button => {
        button.disabled = true;
        if (button.dataset.decision === action) button.textContent = action === "approve" ? "Approving…" : "Rejecting…";
    });

    try {
        const data = await fetchJSON(`/api/approve/${id}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action })
        });

        const expectedStatus = action === "approve" ? "APPROVED" : "REJECTED";
        if (String(data.status).toUpperCase() !== expectedStatus) {
            throw new Error(data.error || `The server did not confirm ${action === "approve" ? "approval" : "rejection"}.`);
        }

        showResult("success", `Request ${expectedStatus.toLowerCase()}`, `Request #${id} was ${action === "approve" ? "approved" : "rejected"}.`, id);
        await refreshAfterDecision();
    } catch (error) {
        if (error.status === 409) {
            showResult("error", "Request already processed", "This request has already been approved or rejected. The queue has been refreshed.", id);
        } else {
            showResult("error", "Decision not completed", error.message, id);
        }
        await refreshAfterDecision();
    } finally {
        state.activeDecisions.delete(id);
        const currentRow = document.querySelector(`.request-row[data-request-id="${id}"]`);
        if (currentRow) currentRow.querySelectorAll(".decision-button").forEach(button => button.disabled = false);
    }
}

// =========================================================
// SECURITY STATISTICS AND HEALTH
// =========================================================

async function loadSecurityStats() {
    try {
        const stats = await fetchJSON("/api/security-stats");
        if (!stats || typeof stats !== "object" || Array.isArray(stats)) throw new Error("Unexpected statistics response.");

        setText("totalCount", stats.total ?? 0);
        setText("pendingCount", stats.pending ?? 0);
        setText("approvedCount", stats.approved ?? 0);
        setText("rejectedCount", stats.rejected ?? 0);
        setText("blockedCount", stats.blocked_ips ?? 0);
        setText("pendingNavCount", stats.pending ?? 0);
        setText("monitorAttacks", stats.attacks ?? 0);
        setText("monitorAlerts", stats.alerts ?? 0);
        setText("monitorBlocked", stats.blocked_ips ?? 0);
        setText("monitorStatus", "MONITORING");
        setText("monitorUpdated", `Updated ${new Date().toLocaleTimeString()}`);
        const status = $("monitorStatus");
        if (status) status.className = "monitoring-label";
        setMessage("monitorError", "");
        return stats;
    } catch (error) {
        setText("monitorStatus", "UNAVAILABLE");
        setMessage("monitorError", `Monitor could not load: ${error.message}`);
        throw error;
    }
}

async function loadSecurityHealth() {
    try {
        const result = await fetchJSON("/api/security-health");
        const score = Math.max(0, Math.min(100, Number(result.score) || 0));
        const status = String(result.status || "UNKNOWN").toUpperCase();

        setText("healthScore", score);
        setText("healthStatus", status);
        setText("healthStatusMessage", `${Number(result.attacks) || 0} recorded attack events and ${Number(result.pending_requests) || 0} pending requests are included in this demo score.`);
        setText("healthUpdated", `Updated ${new Date().toLocaleTimeString()}`);

        const ring = $("healthRing");
        if (ring) {
            ring.style.setProperty("--health-value", `${score * 3.6}deg`);
            ring.dataset.status = status.toLowerCase();
        }
        const statusLabel = $("healthStatus");
        if (statusLabel) statusLabel.className = `status-label ${status.toLowerCase()}`;
        setMessage("healthError", "");
        return result;
    } catch (error) {
        setText("healthStatus", "UNAVAILABLE");
        setText("healthStatusMessage", "The health score could not be loaded.");
        setMessage("healthError", error.message);
        throw error;
    }
}

// =========================================================
// ALERTS
// =========================================================

function alertMarkup(alert) {
    const severity = String(alert.severity || "LOW").toLowerCase();
    return `
        <article class="alert-row ${escapeHTML(severity)}">
            <span class="alert-severity-dot"></span>
            <div class="alert-row-copy">
                <div class="alert-row-title"><strong>${escapeHTML(alert.title || "Security alert")}</strong><span>${escapeHTML(alert.severity || "LOW")}</span></div>
                <p>${escapeHTML(alert.message || "")}</p>
                <small>${escapeHTML(formatDate(alert.created_at))}</small>
            </div>
        </article>`;
}

async function loadAlerts() {
    try {
        const alerts = await fetchJSON("/api/alerts");
        if (!Array.isArray(alerts)) throw new Error("Unexpected alerts response.");

        if (alerts.length === 0) {
            setProtectedPlaceholder("alertList", "No alerts recorded. New security alerts will appear here.");
            setProtectedPlaceholder("overviewAlerts", "No security alerts have been recorded.");
        } else {
            $("alertList").innerHTML = alerts.map(alertMarkup).join("");
            $("overviewAlerts").innerHTML = alerts.slice(0, 3).map(alertMarkup).join("");
        }
        setMessage("alertError", "");
        return alerts;
    } catch (error) {
        setProtectedPlaceholder("alertList", `Could not load alerts: ${error.message}`);
        setProtectedPlaceholder("overviewAlerts", "Could not load alerts.");
        setMessage("alertError", error.message);
        throw error;
    }
}

// =========================================================
// ATTACK ACTIVITY CHART — BACKEND RETURNS DAILY COUNTS
// =========================================================

async function loadAttackChart() {
    const container = $("attackChart");
    try {
        const rows = await fetchJSON("/api/attack-activity");
        if (!Array.isArray(rows)) throw new Error("Unexpected attack activity response.");

        if (rows.length === 0) {
            container.innerHTML = `<div class="empty-block chart-empty"><span>⌁</span><strong>No attack activity recorded</strong><p>Daily activity will appear here when events are recorded.</p></div>`;
            setMessage("attackChartError", "");
            return;
        }

        const max = Math.max(1, ...rows.map(row => Number(row.attacks) || 0));
        container.innerHTML = `
            <div class="bar-chart" role="img" aria-label="Daily attack activity">
                ${rows.map(row => {
                    const count = Math.max(0, Number(row.attacks) || 0);
                    const height = Math.max(5, (count / max) * 100);
                    const dateLabel = String(row.date || "").slice(5);
                    return `
                        <div class="bar-column" title="${escapeHTML(row.date)}: ${count} events">
                            <strong>${count}</strong>
                            <div class="bar-track"><span style="height:${height}%"></span></div>
                            <small>${escapeHTML(dateLabel)}</small>
                        </div>`;
                }).join("")}
            </div>`;
        setMessage("attackChartError", "");
    } catch (error) {
        container.innerHTML = `<p class="inline-error">Chart could not load: ${escapeHTML(error.message)}</p>`;
        setMessage("attackChartError", "");
        throw error;
    }
}

// =========================================================
// THREAT IP LEADERBOARD
// =========================================================

async function loadThreatIPs() {
    const container = $("threatIPList");
    try {
        const rows = await fetchJSON("/api/threat-ips");
        if (!Array.isArray(rows)) throw new Error("Unexpected threat IP response.");

        if (rows.length === 0) {
            container.innerHTML = `<div class="empty-block"><span>⌁</span><strong>No threat IPs recorded</strong><p>Suspicious source addresses will be listed here.</p></div>`;
            setMessage("threatIPError", "");
            return;
        }

        const max = Math.max(1, ...rows.map(row => Number(row.attacks) || 0));
        container.innerHTML = rows.map(row => {
            const attacks = Number(row.attacks) || 0;
            const width = Math.max(4, (attacks / max) * 100);
            return `
                <div class="threat-ip-row">
                    <div class="threat-ip-meta"><strong>${escapeHTML(row.ip || "Unknown")}</strong><span>${attacks} event${attacks === 1 ? "" : "s"}</span></div>
                    <div class="threat-bar"><span style="width:${width}%"></span></div>
                </div>`;
        }).join("");
        setMessage("threatIPError", "");
    } catch (error) {
        container.innerHTML = `<p class="inline-error">Threat IPs could not load: ${escapeHTML(error.message)}</p>`;
        setMessage("threatIPError", "");
        throw error;
    }
}

// =========================================================
// ACTIVITY TIMELINE
// =========================================================

function eventTone(eventName) {
    const event = String(eventName || "").toUpperCase();
    if (event.includes("FAILED") || event.includes("BLOCK") || event.includes("UNAUTHORIZED") || event.includes("DUPLICATE")) return "danger";
    if (event.includes("APPROVED") || event.includes("SUCCESS")) return "success";
    if (event.includes("REQUEST") || event.includes("REJECTED")) return "warning";
    return "neutral";
}

async function loadActivityTimeline() {
    const container = $("timelineList");
    try {
        const rows = await fetchJSON("/api/activity-timeline");
        if (!Array.isArray(rows)) throw new Error("Unexpected timeline response.");

        if (rows.length === 0) {
            container.innerHTML = `<div class="empty-block"><span>◷</span><strong>No activity recorded</strong><p>New events will appear in the timeline.</p></div>`;
        } else {
            container.innerHTML = rows.slice(0, 30).map(row => `
                <article class="timeline-row">
                    <span class="timeline-marker ${eventTone(row.event)}"></span>
                    <div class="timeline-row-body">
                        <div class="timeline-row-head"><strong>${escapeHTML(row.event || "Event")}</strong><time>${escapeHTML(formatDate(row.created_at))}</time></div>
                        <p>${escapeHTML(row.details || "No additional details")}</p>
                        <small>Source: ${escapeHTML(row.ip_address || "Unknown")}</small>
                    </div>
                </article>`).join("");
        }
        setMessage("timelineError", "");
    } catch (error) {
        container.innerHTML = `<p class="inline-error">Timeline could not load: ${escapeHTML(error.message)}</p>`;
        setMessage("timelineError", "");
        throw error;
    }
}

// =========================================================
// AUDIT LOGS AND SEARCH
// =========================================================

function renderAuditLogs() {
    const container = $("logList");
    if (!container) return;
    const query = String($("logSearch").value || "").trim().toLowerCase();
    const rows = state.auditLogs.filter(row => {
        const haystack = `${row.event || ""} ${row.details || ""} ${row.ip_address || ""}`.toLowerCase();
        return haystack.includes(query);
    });

    if (rows.length === 0) {
        container.innerHTML = `<div class="empty-block"><span>⌕</span><strong>${query ? "No matching events" : "No audit events"}</strong><p>${query ? "Try a different search term." : "Recorded events will appear here."}</p></div>`;
        return;
    }

    container.innerHTML = rows.slice(0, 100).map(row => `
        <article class="log-row">
            <div class="log-row-main">
                <strong>${escapeHTML(row.event || "Event")}</strong>
                <p>${escapeHTML(row.details || "")}</p>
                <small>IP ${escapeHTML(row.ip_address || "Unknown")}</small>
            </div>
            <time>${escapeHTML(formatDate(row.created_at))}</time>
        </article>`).join("");
}

async function loadAuditLogs() {
    try {
        const rows = await fetchJSON("/api/logs");
        if (!Array.isArray(rows)) throw new Error("Unexpected audit log response.");
        state.auditLogs = rows;
        renderAuditLogs();
        setMessage("logError", "");
    } catch (error) {
        state.auditLogs = [];
        setProtectedPlaceholder("logList", `Audit logs could not load: ${error.message}`);
        setMessage("logError", "");
        throw error;
    }
}

// =========================================================
// CSV REPORT EXPORT
// =========================================================

function exportReport() {
    if (!state.dashboardUnlocked) {
        showModal("export");
        return;
    }
    setText("exportReportStatus", "Your CSV report is being prepared.");
    window.location.assign("/api/export-report");
}

// =========================================================
// VIEW LOADERS, REFRESH BUTTONS AND POLLING
// =========================================================

async function runLoaders(loaders) {
    await Promise.allSettled(loaders.map(loader => loader()));
}

async function loadViewData(viewName) {
    if (!state.dashboardUnlocked) return;
    const jobs = {
        overview: [loadSecurityStats, loadSecurityHealth, loadAlerts],
        requests: [loadSecurityStats, loadRequests],
        threats: [loadSecurityStats, loadAttackChart, loadThreatIPs],
        activity: [loadActivityTimeline, loadAlerts],
        reports: [loadAuditLogs]
    }[viewName] || [];
    await runLoaders(jobs);
}

async function refreshDashboard() {
    if (!state.dashboardUnlocked) return;
    await loadViewData(state.activeView);
}

function startPolling() {
    if (state.pollingTimer) return;
    state.pollingTimer = setInterval(async () => {
        if (!state.dashboardUnlocked) return;
        const common = [loadSecurityStats];
        const active = {
            overview: [loadSecurityHealth, loadAlerts],
            requests: [loadRequests],
            threats: [loadAttackChart, loadThreatIPs],
            activity: [loadActivityTimeline, loadAlerts],
            reports: [loadAuditLogs]
        }[state.activeView] || [];
        await runLoaders([...common, ...active]);
    }, 30000);
}

function stopPolling() {
    if (state.pollingTimer) clearInterval(state.pollingTimer);
    state.pollingTimer = null;
}

function bindRefresh(id, loader) {
    const button = $(id);
    if (!button) return;
    button.addEventListener("click", async () => {
        if (!state.dashboardUnlocked) {
            showModal("login");
            return;
        }
        button.disabled = true;
        try {
            await loader();
        } catch (error) {
            // The loader itself renders the endpoint error beside its panel.
            console.warn(`Refresh failed for ${id}:`, error.message);
        } finally {
            button.disabled = false;
        }
    });
}

bindRefresh("refreshRequests", loadRequests);
bindRefresh("refreshHealth", loadSecurityHealth);
bindRefresh("refreshMonitor", loadSecurityStats);
bindRefresh("refreshAlerts", loadAlerts);
bindRefresh("refreshAttackChart", loadAttackChart);
bindRefresh("refreshThreatIPs", loadThreatIPs);
bindRefresh("refreshTimeline", loadActivityTimeline);
bindRefresh("refreshLogs", loadAuditLogs);

$("logSearch").addEventListener("input", renderAuditLogs);
$("exportReportButton").addEventListener("click", exportReport);

// =========================================================
// STARTUP — FORCE A FRESH MANAGER SIGN-IN
// =========================================================

 document.addEventListener("DOMContentLoaded", async () => {
    updatePageDate();
    state.dashboardUnlocked = false;
    stopPolling();
    clearProtectedViews();
    setAuthButton();
    switchView("overview");

    // The database was recreated, but the browser may still hold a valid
    // Flask session cookie. Clear that old session so login is always shown
    // when the dashboard is opened or refreshed.
    showModal("login");
    try {
        await fetchJSON("/api/manager-logout", { method: "POST" });
        showModal("login");
    } catch (error) {
        // Keep the modal visible even if session cleanup fails; explain the
        // issue in the modal instead of leaving the dashboard inaccessible.
        showModal("login");
        showLoginError(`Could not reset the previous session: ${error.message}`);
    }
});
