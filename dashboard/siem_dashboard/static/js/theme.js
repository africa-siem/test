/**
 * SIEM Africa - Theme toggle (light/dark)
 *
 * Comportement :
 *  - Click sur #themeToggle inverse le theme
 *  - Sauvegarde le theme dans un cookie 'theme'
 *  - Recharge la page pour appliquer le nouveau theme cote serveur
 */
(function () {
    "use strict";

    function setCookie(name, value, days) {
        const expires = new Date();
        expires.setTime(expires.getTime() + days * 24 * 60 * 60 * 1000);
        document.cookie = `${name}=${value}; expires=${expires.toUTCString()}; path=/; SameSite=Lax`;
    }

    function getCurrentTheme() {
        return document.documentElement.getAttribute("data-theme") || "light";
    }

    function applyThemeToggle() {
        const button = document.getElementById("themeToggle");
        if (!button) return;

        button.addEventListener("click", function () {
            const current = getCurrentTheme();
            const next = current === "dark" ? "light" : "dark";
            setCookie("theme", next, 365);
            // Reload pour que le serveur applique le nouveau theme
            window.location.reload();
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", applyThemeToggle);
    } else {
        applyThemeToggle();
    }
})();
