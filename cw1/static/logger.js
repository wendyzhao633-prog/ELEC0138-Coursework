/**
 * logger.js – Frontend audit logging utility for Student Grade Portal.
 *
 * Usage (include in every page):
 *   <script src="/static/logger.js"></script>
 *
 * All events are:
 *   1. Printed to the browser console in structured JSON.
 *   2. Optionally sent to the backend endpoint POST /audit/frontend.
 *      If the endpoint is unavailable the page still works normally.
 */

(function (window) {
    "use strict";

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /** ISO-8601 timestamp with milliseconds */
    function _now() {
        return new Date().toISOString();
    }

    /** Safe read from localStorage – never throws */
    function _ls(key) {
        try { return localStorage.getItem(key) || undefined; } catch (e) { return undefined; }
    }

    /**
     * Core log dispatcher.
     * Builds a structured event object, prints it, and attempts backend upload.
     *
     * @param {string} action   - Short event label, e.g. "LOGIN_SUCCESS"
     * @param {Object} details  - Arbitrary key-value context
     */
    function logEvent(action, details) {
        details = details || {};

        var event = {
            timestamp:   _now(),
            action:      action,
            page:        window.location.pathname,
            username:    _ls("username"),
            role:        _ls("role"),
            details:     details,
        };

        // Always print to console (formatted)
        console.log(
            "%c[AUDIT] " + action,
            "color: #3182ce; font-weight: bold;",
            event
        );

        // Best-effort upload to backend – silently ignore failures
        _sendToBackend(event);

        return event;
    }

    /**
     * Attempt to POST the event to /audit/frontend.
     * If the endpoint is missing or returns an error, fail silently.
     */
    function _sendToBackend(event) {
        try {
            var token = _ls("token");
            var headers = { "Content-Type": "application/json" };
            if (token) { headers["Authorization"] = "Bearer " + token; }

            fetch("/audit/frontend", {
                method: "POST",
                headers: headers,
                body: JSON.stringify(event),
                // Use keepalive so the request survives page navigation
                keepalive: true,
            }).catch(function () {
                // Silently suppress – backend may not have this route
            });
        } catch (e) {
            // fetch not available or other error – ignore
        }
    }

    // -----------------------------------------------------------------------
    // Public convenience wrappers
    // -----------------------------------------------------------------------

    /**
     * Record a successful login.
     * @param {string} username
     */
    function logLoginSuccess(username) {
        return logEvent("LOGIN_SUCCESS", { username: username });
    }

    /**
     * Record a failed login attempt.
     * @param {string} username
     * @param {string} reason   - e.g. "Invalid credentials", "Empty fields"
     */
    function logLoginFailure(username, reason) {
        return logEvent("LOGIN_FAILURE", {
            username: username,
            reason:   reason || "Unknown",
        });
    }

    /**
     * Record a page visit (call on DOMContentLoaded in each page).
     * @param {string} pageName - Human-readable page name, e.g. "Dashboard"
     */
    function logPageVisit(pageName) {
        return logEvent("PAGE_VISIT", { page_name: pageName });
    }

    /**
     * Record an admin panel access attempt.
     * @param {string}  username
     * @param {boolean} allowed  - true if access was granted
     */
    function logAdminAccessAttempt(username, allowed) {
        return logEvent("ADMIN_ACCESS_ATTEMPT", {
            username: username,
            allowed:  allowed,
            outcome:  allowed ? "GRANTED" : "DENIED",
        });
    }

    /**
     * Record a logout event.
     * @param {string} username
     */
    function logLogout(username) {
        return logEvent("LOGOUT", { username: username });
    }

    /**
     * Record a token missing / expired situation that caused a redirect.
     * @param {string} targetPage - Page the user was trying to reach
     */
    function logTokenMissing(targetPage) {
        return logEvent("TOKEN_MISSING", {
            target_page: targetPage || window.location.pathname,
        });
    }

    /**
     * Record a generic API error.
     * @param {string} endpoint
     * @param {number} status    - HTTP status code
     * @param {string} message
     */
    function logApiError(endpoint, status, message) {
        return logEvent("API_ERROR", {
            endpoint: endpoint,
            status:   status,
            message:  message || "",
        });
    }

    // -----------------------------------------------------------------------
    // Expose on window.Logger
    // -----------------------------------------------------------------------
    window.Logger = {
        logEvent:               logEvent,
        logLoginSuccess:        logLoginSuccess,
        logLoginFailure:        logLoginFailure,
        logPageVisit:           logPageVisit,
        logAdminAccessAttempt:  logAdminAccessAttempt,
        logLogout:              logLogout,
        logTokenMissing:        logTokenMissing,
        logApiError:            logApiError,
    };

})(window);
