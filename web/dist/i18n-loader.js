(function () {
  "use strict";

  // This file is intentionally external: the panel's strict `script-src 'self'`
  // policy blocks inline bootstraps. Because it is parser-inserted, document.write
  // keeps the selected dictionary ahead of app.js without a flash or re-render.
  // WR_PICK: exact code, else the first in the same language (zh-TW/-HK load zh-CN); app.js uses it.
  var langs = window.WR_LANGS || [];
  var pick = (window.WR_PICK = function (tag) {
    tag = String(tag || "").toLowerCase();
    var hit = "";
    for (var i = 0; i < langs.length; i++) {
      var c = langs[i].code, lc = c.toLowerCase();
      if (c === "auto") continue;
      if (lc === tag) return c;
      if (!hit && lc.split("-")[0] === tag.split("-")[0]) hit = c;
    }
    return hit;
  });
  try {
    var language = pick(localStorage.getItem("wr-lang")) || pick(navigator.language || "en");
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
