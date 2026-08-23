(function () {
  "use strict";

  // This file is intentionally external: the panel's strict `script-src 'self'`
  // policy blocks inline bootstraps. Because it is parser-inserted, document.write
  // keeps the selected dictionary ahead of app.js without a flash or re-render.
  try {
    var language = localStorage.getItem("wr-lang") || "";
    if (!language || language === "auto") {
      language = (navigator.language || "en").slice(0, 2).toLowerCase();
    }
    if (language && language !== "en") {
      document.write(
        '<script src="i18n/' +
          encodeURIComponent(language) +
          '.js"><\/script>'
      );
    }
  } catch (_) {
    // Storage can be unavailable in a hardened browser. English literals are
    // dictionary keys, so the panel remains fully usable without a language file.
  }
})();
