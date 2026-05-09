/**
 * SIEM Africa - Dashboard utilities
 *
 * - Auto-refresh (toutes les 10s sur les pages avec data-auto-refresh)
 * - DataTables init helper
 */
(function () {
    "use strict";

    /* ========================================================================
       Auto-refresh
       Sur les pages qui ont <body data-auto-refresh="10"> par exemple,
       on recharge la page automatiquement toutes les N secondes.
       ======================================================================== */
    function initAutoRefresh() {
        const main = document.querySelector("[data-auto-refresh]");
        if (!main) return;
        const seconds = parseInt(main.getAttribute("data-auto-refresh"), 10);
        if (!seconds || seconds < 5) return;

        setTimeout(function () {
            // Pas de reload si l'user est en train d'editer un form
            const activeEl = document.activeElement;
            if (activeEl && (activeEl.tagName === "INPUT" || activeEl.tagName === "TEXTAREA" || activeEl.tagName === "SELECT")) {
                return;
            }
            window.location.reload();
        }, seconds * 1000);
    }

    /* ========================================================================
       DataTables init - applique a toutes les tables avec class .sa-datatable
       ======================================================================== */
    function initDataTables() {
        if (typeof jQuery === "undefined" || typeof jQuery.fn.dataTable === "undefined") {
            return;
        }

        jQuery(".sa-datatable").each(function () {
            const $t = jQuery(this);
            if ($t.hasClass("dataTable")) return;  // deja initialise

            const orderCol = parseInt($t.data("order-col") || "0", 10);
            const orderDir = $t.data("order-dir") || "desc";
            const pageLen = parseInt($t.data("page-length") || "25", 10);

            $t.DataTable({
                pageLength: pageLen,
                order: [[orderCol, orderDir]],
                language: {
                    "decimal": ",",
                    "thousands": " ",
                    "lengthMenu": "Afficher _MENU_ entrees",
                    "zeroRecords": "Aucun resultat",
                    "info": "Page _PAGE_ sur _PAGES_ (_TOTAL_ entrees)",
                    "infoEmpty": "Aucune entree",
                    "infoFiltered": "(filtre sur _MAX_ entrees)",
                    "search": "Rechercher :",
                    "paginate": {
                        "first": "Premier",
                        "last": "Dernier",
                        "next": "Suivant",
                        "previous": "Precedent"
                    }
                }
            });
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", function () {
            initAutoRefresh();
            initDataTables();
        });
    } else {
        initAutoRefresh();
        initDataTables();
    }
})();
