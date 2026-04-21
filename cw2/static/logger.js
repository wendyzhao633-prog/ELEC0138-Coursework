(function (window) {
    "use strict";

    function now() {
        return new Date().toISOString();
    }

    function ls(key) {
        try {
            return window.localStorage.getItem(key) || undefined;
        } catch (_error) {
            return undefined;
        }
    }

    function sendToBackend(event) {
        try {
            var headers = { "Content-Type": "application/json" };
            var token = ls("token");
            if (token) {
                headers.Authorization = "Bearer " + token;
            }

            window.fetch("/audit/frontend", {
                method: "POST",
                headers: headers,
                body: JSON.stringify(event),
                keepalive: true,
            }).catch(function () {});
        } catch (_error) {
        }
    }

    function logEvent(action, details) {
        var event = {
            timestamp: now(),
            action: action,
            page: window.location.pathname,
            username: ls("username"),
            role: ls("role"),
            details: details || {},
        };

        console.log("[AUDIT]", action, event);
        sendToBackend(event);
        return event;
    }

    function logLoginSuccess(username) {
        return logEvent("LOGIN_SUCCESS", { username: username });
    }

    function logLoginFailure(username, reason) {
        return logEvent("LOGIN_FAILURE", {
            username: username,
            reason: reason || "Unknown",
        });
    }

    function logMfaChallenge(username) {
        return logEvent("MFA_CHALLENGE", { username: username });
    }

    function logMfaSuccess(username) {
        return logEvent("MFA_SUCCESS", { username: username });
    }

    function logMfaFailure(username, reason) {
        return logEvent("MFA_FAILURE", {
            username: username,
            reason: reason || "Unknown",
        });
    }

    function logPageVisit(pageName) {
        return logEvent("PAGE_VISIT", { page_name: pageName });
    }

    function logAdminAccessAttempt(username, allowed) {
        return logEvent("ADMIN_ACCESS_ATTEMPT", {
            username: username,
            allowed: allowed,
            outcome: allowed ? "GRANTED" : "DENIED",
        });
    }

    function logLogout(username) {
        return logEvent("LOGOUT", { username: username });
    }

    function logTokenMissing(targetPage) {
        return logEvent("TOKEN_MISSING", { target_page: targetPage || window.location.pathname });
    }

    function logApiError(endpoint, status, message) {
        return logEvent("API_ERROR", {
            endpoint: endpoint,
            status: status,
            message: message || "",
        });
    }

    function logForbidden(endpoint) {
        return logEvent("ACCESS_DENIED", { endpoint: endpoint });
    }

    function logSessionExpiring(secondsRemaining) {
        return logEvent("SESSION_EXPIRING", { seconds_remaining: secondsRemaining });
    }

    window.Logger = {
        logAdminAccessAttempt: logAdminAccessAttempt,
        logApiError: logApiError,
        logEvent: logEvent,
        logForbidden: logForbidden,
        logLoginFailure: logLoginFailure,
        logLoginSuccess: logLoginSuccess,
        logLogout: logLogout,
        logMfaChallenge: logMfaChallenge,
        logMfaFailure: logMfaFailure,
        logMfaSuccess: logMfaSuccess,
        logPageVisit: logPageVisit,
        logSessionExpiring: logSessionExpiring,
        logTokenMissing: logTokenMissing,
    };
})(window);
