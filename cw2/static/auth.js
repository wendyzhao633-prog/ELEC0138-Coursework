(function (window) {
    "use strict";

    var ACCESS_KEYS = ["token", "username", "role", "student_id", "full_name", "email", "token_exp"];
    var FLASH_KEY = "cw2_flash_message";
    var MFA_TOKEN_KEY = "cw2_mfa_temp_token";
    var MFA_USER_KEY = "cw2_mfa_pending_user";
    var warningTimer = null;
    var expiryTimer = null;

    function safeStorage(storage) {
        try {
            return storage;
        } catch (_error) {
            return null;
        }
    }

    function setStorageValue(storage, key, value) {
        var store = safeStorage(storage);
        if (!store) {
            return;
        }
        if (value === null || value === undefined || value === "") {
            store.removeItem(key);
            return;
        }
        store.setItem(key, String(value));
    }

    function getStorageValue(storage, key) {
        var store = safeStorage(storage);
        if (!store) {
            return null;
        }
        return store.getItem(key);
    }

    function removeStorageValue(storage, key) {
        var store = safeStorage(storage);
        if (store) {
            store.removeItem(key);
        }
    }

    function readJson(storage, key) {
        var raw = getStorageValue(storage, key);
        if (!raw) {
            return null;
        }
        try {
            return JSON.parse(raw);
        } catch (_error) {
            return null;
        }
    }

    function writeJson(storage, key, value) {
        setStorageValue(storage, key, JSON.stringify(value));
    }

    function decodeJwtPayload(token) {
        if (!token) {
            return null;
        }
        try {
            var parts = token.split(".");
            if (parts.length < 2) {
                return null;
            }
            var base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
            while (base64.length % 4) {
                base64 += "=";
            }
            return JSON.parse(window.atob(base64));
        } catch (_error) {
            return null;
        }
    }

    function epochSecondsFromToken(token) {
        var payload = decodeJwtPayload(token);
        if (!payload || !payload.exp) {
            return null;
        }
        return Number(payload.exp);
    }

    function nowSeconds() {
        return Math.floor(Date.now() / 1000);
    }

    function clearTimers() {
        window.clearTimeout(warningTimer);
        window.clearTimeout(expiryTimer);
        warningTimer = null;
        expiryTimer = null;
    }

    function setFlash(message, type) {
        if (!message) {
            removeStorageValue(window.sessionStorage, FLASH_KEY);
            return;
        }
        writeJson(window.sessionStorage, FLASH_KEY, {
            message: message,
            type: type || "info",
        });
    }

    function consumeFlash() {
        var value = readJson(window.sessionStorage, FLASH_KEY);
        removeStorageValue(window.sessionStorage, FLASH_KEY);
        return value;
    }

    function showBanner(message, type) {
        var banner = document.getElementById("error-banner");
        if (!banner) {
            return;
        }
        banner.textContent = message;
        banner.className = "alert alert-" + (type || "warning") + " show";
    }

    function hideBanner() {
        var banner = document.getElementById("error-banner");
        if (!banner) {
            return;
        }
        banner.className = "alert";
        banner.textContent = "";
    }

    function clearSession() {
        ACCESS_KEYS.forEach(function (key) {
            removeStorageValue(window.localStorage, key);
        });
    }

    function clearPendingMfa() {
        removeStorageValue(window.sessionStorage, MFA_TOKEN_KEY);
        removeStorageValue(window.sessionStorage, MFA_USER_KEY);
    }

    function storePendingMfa(tempToken, user) {
        setStorageValue(window.sessionStorage, MFA_TOKEN_KEY, tempToken);
        writeJson(window.sessionStorage, MFA_USER_KEY, user || {});
    }

    function getPendingMfa() {
        return {
            temp_token: getStorageValue(window.sessionStorage, MFA_TOKEN_KEY),
            user: readJson(window.sessionStorage, MFA_USER_KEY) || {},
        };
    }

    function storeSession(token, user) {
        var expiry = epochSecondsFromToken(token);
        setStorageValue(window.localStorage, "token", token);
        setStorageValue(window.localStorage, "username", user && user.username);
        setStorageValue(window.localStorage, "role", user && user.role);
        setStorageValue(window.localStorage, "student_id", user && user.student_id);
        setStorageValue(window.localStorage, "full_name", user && user.full_name);
        setStorageValue(window.localStorage, "email", user && user.email);
        setStorageValue(window.localStorage, "token_exp", expiry);
        clearPendingMfa();
    }

    function getUser() {
        return {
            username: getStorageValue(window.localStorage, "username"),
            role: getStorageValue(window.localStorage, "role"),
            student_id: getStorageValue(window.localStorage, "student_id"),
            full_name: getStorageValue(window.localStorage, "full_name"),
            email: getStorageValue(window.localStorage, "email"),
        };
    }

    function redirectToLogin(message, type) {
        clearTimers();
        clearSession();
        clearPendingMfa();
        if (message) {
            setFlash(message, type || "warning");
        }
        if (window.location.pathname !== "/login") {
            window.location.href = "/login";
        }
    }

    function getAccessToken() {
        return getStorageValue(window.localStorage, "token");
    }

    function getAccessExpiry() {
        var stored = getStorageValue(window.localStorage, "token_exp");
        if (stored) {
            return Number(stored);
        }
        return epochSecondsFromToken(getAccessToken());
    }

    function requireAuth() {
        if (!getAccessToken() || !getStorageValue(window.localStorage, "username")) {
            redirectToLogin("Please sign in to continue.", "warning");
            return false;
        }
        return true;
    }

    function initSessionWatch(options) {
        options = options || {};
        clearTimers();

        var expiry = getAccessExpiry();
        if (!expiry) {
            return;
        }

        var secondsRemaining = expiry - nowSeconds();
        if (secondsRemaining <= 0) {
            redirectToLogin("Your session has expired. Please sign in again.", "warning");
            return;
        }

        var warningLeadSeconds = options.warningLeadSeconds || 300;
        var onWarning = options.onWarning || function () {
            showBanner("Session will expire soon. Save your work and sign in again if needed.", "warning");
        };

        if (secondsRemaining <= warningLeadSeconds) {
            onWarning(secondsRemaining);
        } else {
            warningTimer = window.setTimeout(function () {
                onWarning(expiry - nowSeconds());
            }, (secondsRemaining - warningLeadSeconds) * 1000);
        }

        expiryTimer = window.setTimeout(function () {
            redirectToLogin("Your session has expired. Please sign in again.", "warning");
        }, secondsRemaining * 1000);
    }

    function mergeHeaders(existing, contentType) {
        var headers = new window.Headers(existing || {});
        if (contentType && !headers.has("Content-Type")) {
            headers.set("Content-Type", contentType);
        }
        var token = getAccessToken();
        if (token && !headers.has("Authorization")) {
            headers.set("Authorization", "Bearer " + token);
        }
        return headers;
    }

    async function authFetch(url, options) {
        var finalOptions = options ? Object.assign({}, options) : {};
        var body = finalOptions.body;
        var isJsonBody = body && typeof body === "object" && !(body instanceof window.FormData);

        finalOptions.headers = mergeHeaders(finalOptions.headers, isJsonBody ? "application/json" : null);
        if (isJsonBody) {
            finalOptions.body = JSON.stringify(body);
        }

        var response = await window.fetch(url, finalOptions);

        if (response.status === 401) {
            if (window.Logger && typeof window.Logger.logTokenMissing === "function") {
                window.Logger.logTokenMissing(url);
            }
            redirectToLogin("Your session is no longer valid. Please sign in again.", "warning");
            throw new Error("Unauthorized");
        }

        if (response.status === 403) {
            showBanner("Access denied. This action has been logged.", "warning");
            if (window.Logger && typeof window.Logger.logForbidden === "function") {
                window.Logger.logForbidden(url);
            }
        }

        return response;
    }

    window.Auth = {
        authFetch: authFetch,
        clearPendingMfa: clearPendingMfa,
        clearSession: clearSession,
        consumeFlash: consumeFlash,
        decodeJwtPayload: decodeJwtPayload,
        getAccessToken: getAccessToken,
        getPendingMfa: getPendingMfa,
        getUser: getUser,
        hideBanner: hideBanner,
        initSessionWatch: initSessionWatch,
        redirectToLogin: redirectToLogin,
        requireAuth: requireAuth,
        setFlash: setFlash,
        showBanner: showBanner,
        storePendingMfa: storePendingMfa,
        storeSession: storeSession,
    };
})(window);
