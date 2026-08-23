// Mobile nav drawer behaviour, extracted from an inline onclick on .sidebar so
// the panel can ship a strict `script-src 'self'` CSP (an inline event-handler
// attribute would require 'unsafe-inline', which defeats the XSS protection).
// Loaded via <script src> after the markup, so the elements already exist; the
// sidebar/topbar are static (app.js only re-renders #view), so these persist.
(function () {
  "use strict";
  var sidebar = document.querySelector(".sidebar");
  var toggle = document.getElementById("navtoggle");
  var burger = document.querySelector(".nav-burger");

  // The drawer is a CSS-only checkbox (body:has(.nav-toggle:checked)). The burger
  // is a real <button> so it is focusable and Enter/Space activate it natively; we
  // drive the hidden checkbox from its click and mirror the open state to ARIA so
  // assistive tech announces "Menu, collapsed/expanded".
  function syncExpanded() {
    if (burger && toggle) burger.setAttribute("aria-expanded", toggle.checked ? "true" : "false");
  }

  // Toggle the hidden checkbox via a native click (not a bare .checked= set): it
  // flips the state the way a user would, fires "change" (→ syncExpanded), and is
  // the reliable path for the drawer's body:has(.nav-toggle:checked) invalidation.
  if (burger && toggle) {
    burger.addEventListener("click", function () { toggle.click(); });
  }
  // The scrim is also a <label for="navtoggle">; every toggle path — burger,
  // scrim, keyboard — ends in a checkbox "change", so mirror ARIA from there.
  if (toggle) toggle.addEventListener("change", syncExpanded);

  // Tapping any nav item closes the off-canvas drawer (uncheck the CSS toggle).
  if (sidebar) {
    sidebar.addEventListener("click", function (event) {
      if (event.target.closest(".nav-item")) {
        if (toggle) toggle.checked = false;
        syncExpanded();
      }
    });
  }

  syncExpanded(); // initialise from the current state
})();
