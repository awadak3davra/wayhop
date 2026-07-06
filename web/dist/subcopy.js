// Copy button for the subscription landing page (subscription.go serveSubLandingPage).
// Served as a STATIC same-origin file so the page needs no inline <script> — the panel's CSP is
// script-src 'self' (docs/SECURITY.md) and inline scripts are blocked. The subscription URL is
// read from the visible <code id="u"> element instead of a per-token injected JS literal, so this
// file is byte-identical for every token (cacheable, no escaping concerns).
(function () {
  var btn = document.getElementById("copy"), code = document.getElementById("u");
  if (!btn || !code) return;
  btn.addEventListener("click", function () {
    var url = (code.textContent || "").trim();
    function done() { var t = btn.textContent; btn.textContent = "Copied"; setTimeout(function () { btn.textContent = t; }, 1500); }
    function select() {
      try {
        var rng = document.createRange(); rng.selectNodeContents(code);
        var sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(rng);
      } catch (e) { }
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(done, select);
    } else { select(); }
  });
})();
