// page-dns.js — route-scoped chunk for the dns page.
//
// Loaded by loadChunk() the first time that route is opened, NOT from index.html, so its bytes
// stay out of the initial payload the perf budget measures. A classic script, like app.js: these
// declarations become globals and app.js has already defined el/t/api/state by the time this runs.
//
// Everything here is reachable ONLY from this page's renderer — attributed by walking the call
// graph from every render* entry point, counting an identifier anywhere in a body (strings
// included) as a reference, so the shared set is over-estimated and this set is not.
// Writes the DNS plane with the version it was read at, and keeps that version in step with the
// daemon on success. A refusal here is not a failure to retry: the settings on the daemon differ
// from the ones on screen, so the page has to be reloaded before the edit can mean anything.
// Reports a failed DNS write. A staleness refusal is not a retryable error: the plane on screen is
// out of date, so retrying the same submission just gets refused again. Re-rendering re-reads the
// plane and its version, which is the only thing that makes a retry meaningful.
function dnsWriteFailed(e) {
  const stale = /STALE_CONFIG/.test(e.message || "");
  toast((e.message || "").replace(/^STALE_CONFIG:\s*/, ""), "err");
  if (stale) route();
  return stale;
}

// ── Query path ────────────────────────────────────────────────────────────────────────────────
// One picture of where a lookup actually goes: a device on the LAN, the router's :53, the split that
// picks a resolver, the transport that carries it, the exit it leaves through.
//
// The page had all of this before, spread over four cards, and none of it in order. You could read
// the resolver list, the rule list and the leak widget and still not be able to answer "if my laptop
// asks for netflix.com right now, who sees the question?" — which is the only question DNS settings
// are ever changed to affect.
//
// The path has two halves and they are known in different ways, so they are drawn differently:
//
//   CONFIGURED (the fork, the transport, the detour, the exit) is read from the profile. It is always
//   known, because it is what WayHop will emit.
//   RUNTIME (who holds :53, whether LAN clients are forced through it, whether DoT is blocked) has to
//   be measured on the device. Off a router, or when the firewall could not be read, it is UNKNOWN —
//   and an unknown runtime must never be drawn as a clean path, which is the whole point of
//   RulesUnknown existing in the detector.
function dnsQueryPath(nat) {
  const eff = (nat && nat.effective) || null;
  const measured = !!(nat && nat.available && eff);
  const wrap = el("div", { class: "card qp" });
  wrap.appendChild(el("div", { class: "card-head" },
    el("div", { class: "card-title" }, t("Query path")),
    el("div", { class: "acts" },
      el("button", { class: "btn btn-sm", onclick: () => openDNSRule(null) }, t("+ Add rule")))));

  // Stage 1-2: the client and the router's :53.
  const head = el("div", { class: "qp-head" });
  head.appendChild(el("div", { class: "qp-stage" },
    el("div", { class: "qp-stage-l" }, t("LAN client")),
    el("div", { class: "qp-stage-v" }, t("any device")),
    el("div", { class: "qp-stage-s" }, t("asks for a name"))));

  const port = el("div", { class: "qp-stage" },
    el("div", { class: "qp-stage-l" }, t("Port 53 on the router")));
  if (!measured) {
    port.classList.add("unknown");
    port.appendChild(el("div", { class: "qp-stage-v" }, t("not measured")));
    port.appendChild(el("div", { class: "qp-stage-s" },
      nat && nat.available === false
        ? t("This host has no router DNS stack to inspect.")
        : t("WayHop could not read the device, so who holds :53 is unknown.")));
  } else if (eff.rules_unknown) {
    // The distinction AUD-43 exists for: an unreadable firewall is not a firewall with no rules.
    port.classList.add("unknown");
    const who = (eff.listeners || []).map(l => l.process).filter(Boolean);
    port.appendChild(el("div", { class: "qp-stage-v" }, who.length ? who[0] : t("unknown")));
    port.appendChild(el("div", { class: "qp-stage-s" },
      t("The firewall could not be read, so whether LAN DNS is forced here is unknown.")));
  } else {
    const who = (eff.listeners || []).map(l => l.process).filter(Boolean);
    port.appendChild(el("div", { class: "qp-stage-v" }, who.length ? who[0] : t("no listener seen")));
    if (eff.hijack53) {
      port.classList.add("ok");
      port.appendChild(el("div", { class: "qp-stage-s" }, eff.hijack53_to
        ? t("LAN :53 is redirected here ({0})", eff.hijack53_to)
        : t("LAN :53 is redirected here")));
    } else {
      port.classList.add("warn");
      port.appendChild(el("div", { class: "qp-stage-s" }, t("Clients may use their own resolver instead")));
    }
  }
  head.appendChild(port);
  wrap.appendChild(head);

  // Stage 3-6: one row per branch, in the order sing-box evaluates them.
  const rules = (dnsState.rules || []);
  const servers = (dnsState.servers || []);
  const byTag = new Map(servers.map(s => [s.tag, s]));
  const branches = el("div", { class: "qp-branches" });
  // One branch per rule, and 20 rules made this 917px of a 2260px page. Rules are ORDERED and
  // reorderable in place, so this folds rather than filters: every row keeps its position and its
  // move buttons, and a folded row is one click away rather than renumbered or hidden from the
  // ordering. The first few are the ones that decide most queries, being evaluated first.
  const QP_VISIBLE = 4;
  const qpMore = rules.length > QP_VISIBLE
    ? el("details", { class: "qp-more" },
        el("summary", { class: "hint" }, t("Show all {0} rules in order", rules.length)))
    : null;
  branches.appendChild(el("div", { class: "qp-brhead" },
    el("span", {}, "#"),
    el("span", {}, t("When the name matches")),
    el("span", {}, t("Resolver")),
    el("span", {}, t("Transport")),
    el("span", {}, t("Leaves through")),
    el("span", {}, "")));

  // Rows edit in place. The page used to carry a second card listing the same rules with the same
  // targets, so every rule was stated twice and the two could be read in different orders. The path
  // is the truth, so the path is where a rule is reordered, edited and deleted.
  //
  // Real rule rows keep the .dns-rule / .m / order-control classes the reorder gate asserts on; the
  // final catch-all deliberately does NOT, because it is not a rule and must not be counted as a
  // position that can move.
  const branchRow = (n, match, tag, isFinal) => {
    const s = byTag.get(tag);
    const row = el("div", { class: "qp-br" + (isFinal ? " final" : " dns-rule") });
    row.appendChild(el("span", { class: "qp-br-n" }, n));
    row.appendChild(el("span", { class: "qp-br-m m" }, match));
    if (tag === "reject") {
      row.appendChild(el("span", { class: "qp-br-r" }, el("span", { class: "pill err" }, t("blocked"))));
      row.appendChild(el("span", { class: "qp-br-t" }, t("answered locally, never sent")));
      row.appendChild(el("span", { class: "qp-br-e" }, "—"));
    } else if (!s) {
      // A rule pointing at a resolver that no longer exists routes nowhere; saying so beats an
      // empty cell that reads as "direct".
      row.appendChild(el("span", { class: "qp-br-r" }, el("span", { class: "pill err" }, tag || "—")));
      row.appendChild(el("span", { class: "qp-br-t" }, t("no such resolver")));
      row.appendChild(el("span", { class: "qp-br-e" }, "—"));
    } else {
      const enc = DNS_ENC_TYPES.includes(s.type);
      row.appendChild(el("span", { class: "qp-br-r" }, s.tag,
        s.enabled === false ? el("span", { class: "pill muted" }, t("off")) : null));
      row.appendChild(el("span", { class: "qp-br-t" },
        el("span", { class: "badge proto" + (enc ? " enc" : "") }, s.type),
        enc ? null : el("span", { class: "qp-plain", title: t("Unencrypted — whoever carries it can read it") }, t("plaintext"))));
      // The detour IS the exit: an empty one means the query leaves over the raw WAN.
      row.appendChild(el("span", { class: "qp-br-e" }, s.detour
        ? (nameOf(s.detour) || s.detour)
        : el("span", { class: "qp-wan" }, t("WAN (no tunnel)"))));
    }
    return row;
  };

  rules.forEach((r, i) => {
    const parts = (r.rule_sets || []).map(x => nameOf(x) || x)
      .concat(r.domain_suffix || [], r.domain || [], r.geosite || []);
    const match = parts.length ? parts.join(", ") : t("(no match)");
    const row = branchRow(String(i + 1), match, r.server, false);
    if (r.disabled) row.classList.add("off");
    // Exactly the controls the removed card carried, on the row they belong to.
    row.appendChild(el("span", { class: "qp-br-a" },
      // Serialize through dnsSaveChain for the reason the rule editor states: a bare PUT here
      // races a concurrent save. Rule ORDER is meaning - sing-box takes the first match - and
      // two quick arrow clicks sent two writes stamped with the same rev, so the second was
      // refused as stale and rolled back to a snapshot the first had already superseded: the
      // panel showed one order while the router enforced another. Mutating INSIDE the chain
      // operates on the latest state, and adopting r.dns keeps this path identical to every
      // other DNS write.
      orderControls(i, rules.length, "DNS rule " + match, (from, to) => {
        dnsSaveChain = dnsSaveChain.then(async () => {
          const prev = dnsState.rules.slice();
          dnsState.rules = moveInArray(dnsState.rules, from, to);
          try { const r = await dnsPut(); if (r && r.dns) dnsState = r.dns; route(); }
          catch (e) { dnsState.rules = prev; dnsWriteFailed(e); }
        });
        return dnsSaveChain;
      }),
      el("button", { class: "btn btn-sm", "aria-label": t("Edit") + " rule " + match, onclick: () => openDNSRule(i) }, t("Edit")),
      // Identity first, then by unique id — a non-rerendering saveDNS reassigns dnsState and
      // orphans the rule instance this row captured.
      el("button", { class: "btn btn-danger btn-sm", "aria-label": t("Delete") + " rule " + match,
        onclick: async () => {
          if (!await modalConfirm(t("Delete this DNS rule?"))) return;
          let idx = dnsState.rules.indexOf(r);
          if (idx < 0 && r.id) idx = dnsState.rules.findIndex(x => x && x.id === r.id);
          if (idx < 0) return;
          dnsState.rules.splice(idx, 1);
          saveDNS(t("rule ✕"), true);
        } }, t("Delete"))));
    if (qpMore && i >= QP_VISIBLE) qpMore.appendChild(row); else branches.appendChild(row);
  });
  // The fold sits between the last visible rule and the catch-all, so the catch-all stays where it
  // belongs: visually last, because it is what runs when nothing above matched.
  if (qpMore) branches.appendChild(qpMore);
  const finalTag = dnsState.final || (servers[0] && servers[0].tag) || "";
  const finalRow = branchRow("★", t("everything else"), finalTag, true);
  // The catch-all is not editable here: it is the "Default resolver" picker below, and giving it
  // move arrows would imply an order it does not have.
  finalRow.appendChild(el("span", { class: "qp-br-a" }));
  branches.appendChild(finalRow);
  if (!rules.length) {
    branches.appendChild(el("div", { class: "hint qp-norules" },
      t("No rules yet — every query takes the row above. Add one to send chosen names to a different resolver, or to block them at DNS level.")));
  }
  wrap.appendChild(branches);

  // The escape hatch. A perfect chain above means nothing if a client can ignore all of it, and that
  // verdict is only as good as the firewall read that produced it.
  const foot = el("div", { class: "qp-foot" });
  if (!measured) {
    foot.appendChild(el("div", { class: "hint" },
      t("Whether a device can bypass all of this with its own DoH is a runtime question — run WayHop on the router to answer it.")));
  } else if (eff.rules_unknown) {
    foot.appendChild(el("div", { class: "hint qp-unknown" },
      t("⚠ The firewall could not be read, so nothing above about enforcement is confirmed.")));
  // Both, not either. This branch used to fire on the :853 signal alone under a field named for DoH,
  // and told the user nobody could route around the rows above while any browser with its own DoH
  // resolver walked straight past them. The warning below is the honest answer whenever either hatch
  // is open; the daemon's own note says which one and why.
  } else if (eff.doh_bypass_blocked && eff.dot_bypass_blocked) {
    foot.appendChild(el("div", { class: "hint qp-ok" },
      t("✓ Encrypted DNS to other providers (DoT :853) is blocked, so clients cannot route around this.")));
  } else {
    foot.appendChild(el("div", { class: "hint qp-warn" },
      t("⚠ A device with its own DoH or DoT resolver bypasses every row above. Nothing here blocks it.")));
  }
  wrap.appendChild(foot);
  return wrap;
}

// dnsPathNote says what a resolver's detour MEANS: which exit its queries leave through, and — the
// question the page could not answer — whether they may fall back to the provider when that exit is
// gone. The row showed "via X" and stopped, which reads as a setting rather than as the behaviour it
// buys: a tunnel detour hides the query but takes DNS down with the tunnel, while a failover group
// ending in `direct` keeps resolving over the raw WAN (still encrypted, but the provider sees whom
// you asked). Those are opposite trade-offs and they looked identical.
function dnsPathNote(detour) {
  detour = (detour || "").trim();
  if (detour === "" || detour === "direct") {
    return { cls: "hint", text: t("leaves through the provider — never hidden") };
  }
  const g = (state.profile.groups || []).find(x => x.id === detour);
  if (!g) {
    return { cls: "hint dns-path-strict", text: t("tied to one tunnel — DNS stops if it goes down") };
  }
  const members = g.members || [];
  const last = members[members.length - 1];
  if (last === "direct") {
    return { cls: "hint", text: t("falls back to the provider when every tunnel is down") };
  }
  return { cls: "hint dns-path-strict", text: t("no provider fallback — DNS stops if every member is down") };
}

// dnsFilterBox makes a long DNS page navigable the way Routing and Settings already are.
//
// This page opens taller than two screens on a router with real resolvers and rules on it, and the
// thing an operator arrives looking for is one row: a resolver, a domain, a switch by name. Scrolling
// past everything else to reach it is the cost a filter removes. The rule the whole page obeys is the
// one the density gate states: make the overflow navigable, never hide it behind an inner scrollbar.
//
// Typing hides non-matching ROWS, and a card left with no matching row hides with them. A card that
// carries no filterable rows at all — the query path, the leak widget — is scenery for the whole page
// rather than an answer to a search, so it steps aside while a search is active and returns intact
// when the box is cleared.
function dnsFilterBox(view) {
  const inp = el("input", {
    type: "search", placeholder: t("Filter DNS — resolver, domain or setting"),
    "aria-label": t("Filter DNS — resolver, domain or setting"),
  });
  const apply = () => {
    const q = inp.value.trim().toLowerCase();
    view.querySelectorAll(".card").forEach(card => {
      const rows = [...card.querySelectorAll(".dns-row, .dns-rule, .dns-tog")];
      if (!q) {
        card.hidden = false;
        rows.forEach(r => { r.hidden = false; });
        return;
      }
      let shown = 0;
      rows.forEach(r => {
        const hit = (r.textContent || "").toLowerCase().includes(q);
        r.hidden = !hit;
        if (hit) shown++;
      });
      card.hidden = shown === 0;
    });
  };
  inp.addEventListener("input", apply);
  return el("div", { class: "field dns-filter" }, inp);
}

// dnsToggleRow — a labelled accessible switch bound to a boolean key on dnsState. Optimistic: flips
// the switch, mutates state, PUTs; saveDNS's error path re-renders from the persisted state (reverting
// a rejected flip). fakeip forces independent_cache (sing-box requires the pairing; validateDNS 400s).
// gate: { key, reason } when this switch does nothing until another one is on. "Break hardcoded
// encrypted resolvers" is the case it exists for: keeneticPBROptionsFor only passes
// DNSRejectEncrypted through inside "if p.DNS.Intercept", so with interception off the switch stores
// true and installs no rule at all - while its own hint promises those clients "fall back to plain
// DNS and are intercepted", which cannot happen. Measured on the demo: flipping it alone toasted a
// plain confirmation and saved intercept_reject_encrypted:true against intercept:false.
//
// The dependency is NOT resolved by turning interception on for the operator. That redirects every
// client's DNS to this router, which is a decision with its own consequences and its own switch one
// row above; making it a side effect of a different click is how a router starts answering queries
// nobody asked it to answer.
function dnsToggleRow(label, key, hint, gate) {
  const blocked = gate && !dnsState[gate.key] ? gate.reason : "";
  const sw = switchEl(!!dnsState[key], (s) => {
    if (applyInFlight) { toast(t("Apply in progress — finish it first"), "err"); return; } // don't mutate staged DNS mid-Apply (checked before flipSwitch, so no visual desync)
    // Only the ON direction is refused. Switching an already-stored no-op back OFF is cleanup and
    // must always be possible: a gate that locks a setting into the state it should not be in is a
    // worse trap than the silent no-op it was meant to prevent.
    if (blocked && !dnsState[key]) { toast(blocked, "err"); return; }
    const want = !dnsState[key];
    flipSwitch(s, want);
    dnsState[key] = want;
    if (key === "fakeip" && want) dnsState.independent_cache = true;
    // Switching a gated row OFF closes the only door it had: it can no longer be turned back on while
    // its gate is shut, so it must READ unavailable from this click, not from the next render that
    // happens to come along.
    if (blocked) { setGateLook(s, !want, blocked); }
    // A switch other rows depend on must redraw the page: leaving a dependent row enabled after its
    // gate closed (or greyed after it opened) is the same stale-state lie in the other direction.
    saveDNS(label + (want ? " ✓" : " ✕"), DNS_GATE_KEYS.has(key));
  }, label);
  // Greyed only while it cannot be turned ON. Already on and inert stays clickable, and the hint
  // below says why it is doing nothing.
  setGateLook(sw, blocked && !dnsState[key], blocked);
  return el("div", { class: "dns-tog" },
    el("div", { class: "top" }, el("label", {}, label), sw),
    hint ? el("div", { class: "hint" }, blocked ? blocked + " " + hint : hint) : null);
}

// setGateLook marks a switch as unavailable-rather-than-off, in one place so the render and the
// click agree on what unavailable looks like.
function setGateLook(sw, unavailable, reason) {
  if (unavailable) { sw.setAttribute("aria-disabled", "true"); sw.title = reason; }
  else { sw.removeAttribute("aria-disabled"); sw.title = ""; }
}

// The keys another row is gated on. Flipping one changes whether a different switch can act at all.
const DNS_GATE_KEYS = new Set(["intercept"]);



// openNativePlan previews the native write-back: POSTs the adopted NativeDNS to /api/dns/native/plan
// and shows the exact uci (OpenWrt) / dnsmasq.d (Keenetic) the router WOULD get, plus the separate
// user-gated apply commands. Nothing is applied — this is the safe, offline-verifiable end of the wiring.
// mainConfUpstreams counts the adopted upstreams that came from the router's MAIN dnsmasq config
// rather than from the conf-dir this plan writes into. The reader tags each one (see
// DnsmasqDirSentinel); before it did, every upstream claimed to come from the conf-dir and this
// question could not be asked at all.
function mainConfUpstreams(nat) {
  return (((nat || {}).native || {}).resolvers || [])
    .filter(x => String(x.source || "").startsWith("dnsmasq.conf")).length;
}

async function openNativePlan(nat) {
  try {
    const r = await api.post("/api/dns/native/plan", { native: nat.native });
    const body = el("div", {},
      el("div", { class: "hint", style: "margin-bottom:8px" }, t("What writing the current native DNS back to your router would change. Nothing is applied automatically — the apply step is manual/gated.")),
      // What this write does NOT touch. The plan renders 00-upstream.conf INSIDE the conf-dir, and
      // dnsmasq merges that directory into the main config — so an upstream that already lives in
      // /opt/etc/dnsmasq.conf is not replaced by applying this, it gains a second copy, along with a
      // second strict-order and no-resolv. Measured on a live Keenetic: the plan proposes
      // exactly the four directives his main config already carries, and the card labelled them
      // "dnsmasq.conf server" one line above — the preview said nothing about the collision.
      mainConfUpstreams(nat) && r.platform !== "openwrt"
        ? el("div", { class: "hint upd-err", style: "margin-bottom:8px" },
          t("{0} of these upstreams already sit in the router's main dnsmasq config, which this write does not touch — dnsmasq merges the conf-dir into it, so applying adds a second copy rather than replacing them.", mainConfUpstreams(nat)))
        : null,
      el("div", { class: "name", style: "margin:6px 0 4px" }, r.platform === "openwrt" ? t("uci commands") : t("dnsmasq.d content")),
      el("pre", { class: "code", style: "max-height:38vh;overflow:auto;white-space:pre-wrap;margin:0" }, r.content || ""),
      el("div", { class: "name", style: "margin:12px 0 4px" }, t("Then, to apply (user-gated):")),
      el("pre", { class: "code", style: "max-height:20vh;overflow:auto;white-space:pre-wrap;margin:0" }, (r.apply || []).join("\n")));
    const back = modal({ title: t("Native DNS write-back plan"), body, footer: el("button", { class: "btn", onclick: () => back.close() }, t("Close")) });
  } catch (e) { toast(e.message, "err"); }
}

function dnsServerRow(s, i) {
  const net = DNS_NET_TYPES.includes(s.type);
  const enc = DNS_ENC_TYPES.includes(s.type);
  const addr = net ? (s.server + (s.server_port ? ":" + s.server_port : "") + (s.path || "")) : (s.type === "fakeip" ? (s.inet4_range || "198.18.0.0/15") : t("device resolver"));
  const leakWarn = (net && !enc) ? el("span", { class: "pill err", title: t("plaintext DNS — the ISP can read your queries") }, t("⚠ plaintext")) : null;
  const via = net ? "via " + (nameOf(s.detour) || (s.detour ? s.detour : t("direct"))) : null;
  const path = net ? dnsPathNote(s.detour) : null;
  return el("div", { class: "dns-row" },
    el("span", { class: "badge" }, DNS_TYPE_BADGE[s.type] || s.type),
    el("div", { class: "main" },
      el("div", { class: "name" }, el("span", { class: "tag" }, s.tag), leakWarn),
      el("div", { class: "sub" }, el("span", { class: "addr" }, addr), via ? el("span", {}, "· " + via) : null,
        path ? el("span", { class: path.cls }, "· " + path.text) : null)),
    el("div", { class: "acts" },
      el("button", { class: "btn btn-sm", "aria-label": t("Edit") + " resolver " + s.tag, onclick: () => openDNSServer(i) }, t("Edit")),
      // Identity first (robust to in-flight index shifts), then by unique tag: a non-rerendering
      // saveDNS (toggle/strategy/default-resolver) reassigns dnsState to fresh round-tripped
      // instances while the rendered rows still close over the OLD objects, so indexOf(s) alone
      // returns -1 and the confirmed delete silently no-ops until a re-render.
      el("button", { class: "btn btn-danger btn-sm", onclick: async () => { if (!await modalConfirm(t("Delete DNS resolver {0}?", s.tag))) return; let idx = dnsState.servers.indexOf(s); if (idx < 0) idx = dnsState.servers.findIndex(x => x && x.tag === s.tag); if (idx < 0) return; dnsState.servers.splice(idx, 1); if (dnsState.final === s.tag) dnsState.final = ""; saveDNS(s.tag + " ✕", true); } , "aria-label": t("Delete") + " resolver " + s.tag }, t("Delete"))));
}

function dnsNativeRow(rz) {
  const kind = (rz.kind || "").toUpperCase();
  const badge = kind === "PLAIN" ? "Do53" : (kind === "DOH" ? "DoH" : (kind === "DOT" ? "DoT" : (kind === "LOCAL" ? "Local" : kind)));
  const tier = el("span", {}, t(DNS_TIER_LABEL[rz.tier] || ("tier " + rz.tier)));
  return el("div", { class: "dns-row" },
    el("span", { class: "badge" }, badge),
    el("div", { class: "main" },
      el("div", { class: "name" }, el("span", { class: "tag" }, rz.address || "")),
      el("div", { class: "sub" }, tier, rz.via_tunnel ? el("span", {}, "· " + t("via tunnel")) : null)),
    // The source is a config identifier of unbounded length and its column is now sized from the
    // container, so a long one truncates. title keeps the full value recoverable.
    el("div", { class: "acts" }, el("span", { class: "pill muted", title: rz.source || "" }, rz.source || "")));
}

function dnsSuggestTag(p) {
  const base = (p.name || p.type || "dns").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 24) || "dns";
  const taken = new Set(dnsState.servers.map(s => s.tag));
  let tag = base, n = 1;
  while (taken.has(tag)) tag = base + "_" + (++n);
  return tag;
}

async function openDNSServer(idx) {
  const editing = idx != null;
  const cur = editing ? dnsState.servers[idx] : { type: "https", enabled: true, path: "/dns-query", detour: primaryDetourGuess() };
  let presets = [];
  try { presets = (await api.get("/api/dns/catalog")).presets || []; } catch (_) {}

  // Group the picker: recommended secure/global resolvers vs country-local (geo-fallback) ones.
  // Option values stay the ORIGINAL preset index, so the onchange handler is unchanged.
  const presetSel = el("select", { id: "dnsm-preset" }, el("option", { value: "" }, t("— choose a provider —")));
  [["", t("Recommended — secure, global")], ["local", t("Country-local — geo-fallback")]].forEach(([cat, label]) => {
    const items = presets.map((p, i) => [p, i]).filter(([p]) => (p.category || "") === cat);
    if (items.length) presetSel.appendChild(el("optgroup", { label },
      ...items.map(([p, i]) => el("option", { value: String(i), title: p.note || "" }, p.name))));
  });
  const tagIn = el("input", { id: "dnsm-tag", type: "text", value: cur.tag || "", placeholder: "dns_secure" });
  const typeSel = el("select", { id: "dnsm-type" }, ...Object.keys(DNS_TYPE_LABEL).map(x => el("option", { value: x }, DNS_TYPE_LABEL[x])));
  typeSel.value = cur.type || "https";
  const serverIn = el("input", { id: "dnsm-server", type: "text", value: cur.server || "", placeholder: "1.1.1.1" });
  const portIn = el("input", { id: "dnsm-port", type: "number", value: cur.server_port || "", placeholder: "443" });
  const pathIn = el("input", { id: "dnsm-path", type: "text", value: cur.path || "", placeholder: "/dns-query" });
  const detourSel = routingOutboundSelect(cur.detour || "direct", false); detourSel.id = "dnsm-detour";
  const bootSel = el("select", { id: "dnsm-boot" }, el("option", { value: "" }, t("(none — server is an IP)")),
    ...dnsState.servers.filter((_, j) => j !== idx).map(x => el("option", { value: x.tag }, x.tag)));
  bootSel.value = cur.domain_resolver || "";
  const i4In = el("input", { id: "dnsm-i4", type: "text", value: cur.inet4_range || "198.18.0.0/15", placeholder: "198.18.0.0/15" });
  const i6In = el("input", { id: "dnsm-i6", type: "text", value: cur.inet6_range || "", placeholder: "fc00::/18" });
  const enChk = el("input", { id: "dnsm-en", type: "checkbox" }); if (cur.enabled !== false) enChk.setAttribute("checked", "true");

  const rowServer = el("div", { class: "field" }, el("label", {}, t("Server (IP or hostname)")), serverIn);
  const rowPort = el("div", { class: "field" }, el("label", {}, t("Port (blank = default)")), portIn);
  const rowPath = el("div", { class: "field" }, el("label", {}, t("DoH path")), pathIn);
  const rowDetour = el("div", { class: "field" }, el("label", {}, t("Ride via (detour)")), detourSel);
  const rowBoot = el("div", { class: "field" }, el("label", {}, t("Bootstrap resolver (hostname only)")), bootSel);
  const rowI4 = el("div", { class: "field" }, el("label", {}, t("FakeIP IPv4 range")), i4In);
  const rowI6 = el("div", { class: "field" }, el("label", {}, t("FakeIP IPv6 range (optional)")), i6In);

  const sync = () => {
    const ty = typeSel.value;
    const net = DNS_NET_TYPES.includes(ty), enc = DNS_ENC_TYPES.includes(ty), fake = ty === "fakeip";
    rowServer.style.display = net ? "" : "none";
    rowPort.style.display = net ? "" : "none";
    rowPath.style.display = (ty === "https" || ty === "h3") ? "" : "none";
    rowDetour.style.display = net ? "" : "none";
    rowBoot.style.display = enc ? "" : "none";
    rowI4.style.display = fake ? "" : "none";
    rowI6.style.display = fake ? "" : "none";
  };
  typeSel.onchange = sync;
  presetSel.onchange = () => {
    if (!presetSel.value) return; // placeholder ("— choose a provider —") selected — guard the RAW string: +"" coerces to 0 and would silently load presets[0]
    const p = presets[+presetSel.value];
    if (!p) return;
    typeSel.value = p.type;
    if (p.server != null) serverIn.value = p.server;
    portIn.value = p.server_port || "";
    pathIn.value = p.path || "";
    if (!tagIn.value.trim()) tagIn.value = dnsSuggestTag(p);
    sync();
  };

  const body = el("div", {},
    el("div", { class: "field" }, el("label", {}, t("Provider preset")), presetSel),
    el("div", { class: "field" }, el("label", {}, t("Tag")), tagIn),
    el("div", { class: "field" }, el("label", {}, t("Type")), typeSel),
    rowServer, rowPort, rowPath, rowDetour, rowBoot, rowI4, rowI6,
    el("label", { class: "check" }, enChk, el("span", {}, t("Enabled"))));

  const saveBtn = el("button", { class: "btn btn-primary" }, t("Save"));
  const back = modal({
    title: editing ? t("Edit resolver") : t("Add resolver"),
    body,
    footer: [el("button", { class: "btn", onclick: () => back.close() }, t("Cancel")), saveBtn],
  });
  sync();
  saveBtn.onclick = async () => {
    const ty = typeSel.value;
    const o = { tag: tagIn.value.trim(), type: ty, enabled: enChk.checked };
    if (!o.tag) { toast(t("Tag is required"), "err"); return; }
    if (DNS_NET_TYPES.includes(ty)) {
      o.server = serverIn.value.trim();
      const port = parseInt(portIn.value, 10); if (port) o.server_port = port;
      const det = detourSel.value; if (det && det !== "direct") o.detour = det;
      const boot = bootSel.value; if (boot) o.domain_resolver = boot;
      if (ty === "https" || ty === "h3") { const pth = pathIn.value.trim(); if (pth) o.path = pth; }
    }
    if (ty === "fakeip") {
      o.inet4_range = i4In.value.trim() || "198.18.0.0/15";
      const i6 = i6In.value.trim(); if (i6) o.inet6_range = i6;
    }
    saveBtn.disabled = true;
    // Serialize through dnsSaveChain like saveDNS() — a direct PUT + dnsState reassignment here
    // can race a concurrent background saveDNS() (toggle/strategy/default) and clobber dnsState.
    // Mutating inside the chained step also means it operates on the latest dnsState, not a stale one.
    dnsSaveChain = dnsSaveChain.then(async () => {
      const prev = dnsState.servers.slice();
      if (editing) dnsState.servers[idx] = o; else dnsState.servers.push(o);
      if (dnsState.fakeip && ty === "fakeip") dnsState.independent_cache = true;
      try {
        const r = await dnsPut();
        if (r && r.dns) dnsState = r.dns;
        state.profile.dns = dnsState; updateDirty();
        toast(editing ? t("Resolver updated") : t("Resolver added"), "ok");
        back.close(); route();
      } catch (e) {
        dnsState.servers = prev; saveBtn.disabled = false;
        if (dnsWriteFailed(e)) back.close();
      }
    });
    await dnsSaveChain;
  };
}

function openDNSRule(idx) {
  const editing = idx != null;
  const cur = editing ? dnsState.rules[idx] : { rule_sets: [], domain_suffix: [], query_type: [], server: dnsState.servers[0] ? dnsState.servers[0].tag : "reject" };
  const lists = state.profile.routing_lists || [];
  const listBox = el("div", { style: "max-height:160px;overflow:auto;border:1px solid var(--border);border-radius:6px;padding:8px" });
  if (!lists.length) listBox.appendChild(el("div", { class: "hint" }, t("No routing lists — add one under Routing to match by list.")));
  const listChecks = {};
  lists.forEach(rl => {
    const c = el("input", { type: "checkbox" }); if ((cur.rule_sets || []).includes(rl.id)) c.setAttribute("checked", "true");
    listChecks[rl.id] = c;
    listBox.appendChild(el("label", { class: "check" }, c, el("span", {}, rl.name || rl.id)));
  });
  // asList, not `|| []`: these come from the stored rule and a scalar there throws while the form is
  // being built, so the dialog never opens at all — see app.js and the endpoint whose local_address
  // was a string.
  const sufIn = el("textarea", { id: "dnsr-suf", rows: "3", placeholder: "example.com\ninternal.lan" }, asList(cur.domain_suffix).join("\n"));
  const qtIn = el("input", { id: "dnsr-qt", type: "text", value: asList(cur.query_type).join(","), placeholder: "A,AAAA" });
  const srvSel = el("select", { id: "dnsr-srv" }, ...dnsState.servers.map(s => el("option", { value: s.tag }, s.tag)), el("option", { value: "reject" }, t("Block (reject)")));
  srvSel.value = cur.server || "reject";

  const body = el("div", {},
    el("div", { class: "field" }, el("label", {}, t("Match routing lists")), listBox),
    el("div", { class: "field" }, el("label", {}, t("Domain suffixes (one per line)")), sufIn),
    el("div", { class: "field" }, el("label", {}, t("Query types (comma-separated, e.g. A,AAAA)")), qtIn),
    el("div", { class: "field" }, el("label", {}, t("Resolve via")), srvSel));

  const saveBtn = el("button", { class: "btn btn-primary" }, t("Save"));
  const back = modal({
    title: editing ? t("Edit DNS rule") : t("Add DNS rule"),
    body,
    footer: [el("button", { class: "btn", onclick: () => back.close() }, t("Cancel")), saveBtn],
  });
  saveBtn.onclick = async () => {
    // Spread `cur` first so fields this modal does NOT expose (geosite, domain, disabled — settable
    // via the API / an imported config and rendered in the rule row) are preserved on edit instead
    // of being silently dropped by a from-scratch rebuild; the edited fields below then override.
    const o = Object.assign({}, cur, {
      id: (editing && cur.id) ? cur.id : ("r" + Date.now().toString(36)),
      rule_sets: Object.keys(listChecks).filter(id => listChecks[id].checked),
      domain_suffix: sufIn.value.split("\n").map(x => x.trim()).filter(Boolean),
      query_type: qtIn.value.split(",").map(x => x.trim()).filter(Boolean),
      server: srvSel.value,
    });
    if (!o.rule_sets.length && !o.domain_suffix.length && !o.query_type.length) { toast(t("A rule needs at least one match condition"), "err"); return; }
    saveBtn.disabled = true;
    // Serialize through dnsSaveChain like saveDNS() so this PUT + dnsState reassignment can't race
    // a concurrent background saveDNS() and clobber dnsState (mutate inside → operates on latest state).
    dnsSaveChain = dnsSaveChain.then(async () => {
      const prev = dnsState.rules.slice();
      if (editing) dnsState.rules[idx] = o; else dnsState.rules.push(o);
      try {
        const r = await dnsPut();
        if (r && r.dns) dnsState = r.dns;
        state.profile.dns = dnsState; updateDirty();
        toast(t("Rule saved"), "ok"); back.close(); route();
      } catch (e) {
        dnsState.rules = prev; saveBtn.disabled = false;
        if (dnsWriteFailed(e)) back.close();
      }
    });
    await dnsSaveChain;
  };
}

async function previewDNS() {
  try {
    const gen = await api.post("/api/generate", {});
    const dns = gen && gen.config && gen.config.dns;
    const pre = el("pre", { class: "code", style: "max-height:60vh;overflow:auto;white-space:pre-wrap;margin:0" },
      dns ? JSON.stringify(dns, null, 2) : t("No dns block — enable DNS management first."));
    const back = modal({ title: t("Generated dns block"), body: pre, footer: el("button", { class: "btn", onclick: () => back.close() }, t("Close")) });
  } catch (e) { toast(e.message, "err"); }
}

async function applyDNSSecureDefaults() {
  if (dnsState && dnsState.servers && dnsState.servers.length &&
    !await modalConfirm(t("Replace the current DNS setup with the secure defaults (encrypted DoH via the tunnel + local, leak-proof)?"))) return;
  try {
    const resp = await api.get("/api/dns?template=1");
    // Assign dnsState INSIDE the save chain (like openDNSServer/openDNSRule) so a background saveDNS()
    // still in flight can't clobber this template — nor this reassignment clobber that chained save.
    dnsSaveChain = dnsSaveChain.then(() => { dnsState = resp.dns; return saveDNSNow(t("Applied secure DNS defaults"), true); });
    await dnsSaveChain;
  } catch (e) { toast(e.message, "err"); }
}

function dnsLeakWidget() {
  const card = el("div", { class: "card" });
  const body = el("div", {}, el("div", { class: "hint" }, t("Checks that lookups are private (DoH) and that no IPv6 path leaks around the tunnel. Runs the same server-side probes as Diagnostics.")));
  card.appendChild(el("div", { class: "card-head" },
    el("div", { class: "card-title" }, t("DNS leak test")),
    el("div", { class: "acts" }, el("button", { class: "btn btn-sm", onclick: () => runDNSLeak(body) }, t("Run test")))));
  card.appendChild(body);
  return card;
}

async function runDNSLeak(body) {
  body.textContent = ""; body.appendChild(el("div", { class: "hint" }, t("Testing…")));
  try {
    const d = await api.get("/api/healthcheck");
    const rows = (d.checks || []).filter(c => c.id === "dns" || c.id === "ipv6");
    body.textContent = "";
    if (!rows.length) { body.appendChild(el("div", { class: "hint" }, t("No DNS probe available on this device."))); return; }
    rows.forEach(c => {
      // Backend healthcheck status enum is pass | warn | fail | na (never "ok"). Every value is named
      // here, because the fall-through is the RED pill: mapping "pass" alone once turned a leak-free
      // check into a false alarm, and leaving "na" unnamed would do it again to a check that simply
      // did not run — the dns/ipv6 rows report exactly that on a host with nothing to read.
      const cls = c.status === "pass" ? "ok" : c.status === "warn" ? "warn" : c.status === "na" ? "muted" : "err";
      body.appendChild(el("div", { style: "display:flex;align-items:center;justify-content:space-between;gap:10px;padding:5px 0" },
        el("span", {}, c.label || c.id),
        el("span", { class: "pill " + cls, title: c.detail || "" }, c.summary || c.status)));
      // A check that did not run carries no advice worth acting on.
      if (c.status !== "pass" && c.status !== "na" && c.fix) body.appendChild(el("div", { class: "hint" }, "→ " + c.fix));
    });
  } catch (e) { body.textContent = ""; body.appendChild(el("div", { class: "hint" }, t("Leak test unavailable: ") + e.message)); }
}
