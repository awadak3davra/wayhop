// page-updater.js — the components/updater page, loaded on demand by loadChunk() when #updater is
// first opened. See PAGES.updater.chunk in app.js.
//
// It is a route chunk because nothing else in the panel reads it: no other page calls a single
// function declared here (verified by check-chunks), and the initial payload is what the perf budget
// measures. renderUpdater itself stays in app.js — PAGES holds the function VALUE at module load,
// long before this file exists — and it runs only after loadChunk has resolved, so every helper
// below is defined by the time it is called.

// ── Update sweep ──────────────────────────────────────────────────────────────────────────────
// One question leads the page: what is behind right now.
//
// The old layout answered it nowhere. WayHop checked itself on load, every engine waited for its own
// "Check updates" click, and each got a card — so eight cards said eight local things and the reader
// had to hold the summary in their head. Worse, an unchecked component looked identical to a current
// one: neither said anything, and silence reads as fine.
//
// So the checks fan out from one button, and the verdict counts the five states apart instead of
// collapsing them into up-to-date/not:
//
//   behind        a comparison ran and said so
//   current       a comparison ran and said so
//   cannot compare  a rolling tag (nightly/latest) with no version in it — this is the AUD case
//                 where "not newer" and "could not decide" were the same false
//   not checked   nobody has asked yet
//   check failed  the ask errored
//
// A verdict that folds the last three into "current" is the exact defect this project keeps finding,
// and on an update page it is the one that leaves a router unpatched.
const UPD_STATE_ORDER = ["behind", "error", "channel_missing", "undecidable", "unchecked", "ahead", "current", "absent"];

// updRows is the page's model, keyed by component id. Rebuilt on render; mutated in place by the
// per-row and fan-out checks so the verdict can be recomputed without a full re-render.
let updRows = new Map();

// The catalog-only engines, kept apart from updRows. They are NOT in the verdict — this router will
// never run them, and counting them would pin "not checked" on forever — but a button labelled
// "Check all" that skipped them was a name promising more than it did. The sweep covers both; only
// the verdict is scoped.
let updAdvRows = new Map();

// downloadPathRow lets the operator choose which connection a component download leaves through.
//
// It exists for the case that makes this whole section useless otherwise: where the router's ordinary
// path to the release is blocked, nothing can be installed — including the engine that would have
// carried the traffic around the block. There is no downloading your way out of that, so the download
// has to be able to take a tunnel that still works. Routing lists already carry the same idea per
// list ("Download the list via"); this is the same question for the router's own downloads.
//
// The row states what is in FORCE, not just what is saved: a tunnel that was deleted or switched off
// resolves to nothing and the download quietly takes the ordinary path, which the operator has to be
// able to see.
function downloadPathRow(storage) {
  const sel = el("select", { "aria-label": t("Download components through") });
  sel.appendChild(el("option", { value: "" }, t("the router's ordinary path")));
  // The daemon says what can carry a download; this page does not work it out.
  //
  // It used to read state.profile, and that was wrong in both directions. Opened cold — the way an
  // operator arrives when they want to install something — Components has no profile yet, so the list
  // was just "the ordinary path" and every tunnel was missing. And a profile that HAD loaded offered
  // proxy endpoints too, which have no kernel link to bind to, so choosing one quietly did nothing.
  (storage.download_paths || []).forEach(p =>
    sel.appendChild(el("option", { value: p.id }, p.group ? t("{0} (group)", p.name) : p.name)));
  sel.value = storage.download_via || "";
  // A saved choice the profile no longer offers must stay visible rather than silently reading as
  // "ordinary path" — the operator chose something and it is gone.
  if (storage.download_via && sel.value !== storage.download_via) {
    sel.appendChild(el("option", { value: storage.download_via }, t("{0} — no longer in the profile", storage.download_via)));
    sel.value = storage.download_via;
  }
  const note = el("span", { class: "hint" });
  const say = () => {
    // With nothing to offer, say WHY rather than leaving a control that appears to do nothing. On a
    // router whose exits are all carried by an engine there is no link to bind a download to, and the
    // operator hunting for a way around a blocked path needs to know this control cannot provide one.
    if (!(storage.download_paths || []).length) {
      note.textContent = t("no tunnel here can carry a download — every exit is carried by an engine, not by a network link");
      return;
    }
    note.textContent = storage.download_iface
      ? t("in force: through {0}", storage.download_iface)
      : (sel.value ? t("not in force — that connection cannot carry it, downloads take the ordinary path")
        : t("downloads go out the way the router routes everything else"));
  };
  say();
  sel.addEventListener("change", async () => {
    sel.disabled = true;
    try {
      const cfg = await api.get("/api/config");
      cfg.updater = Object.assign({}, cfg.updater, { download_via: sel.value });
      await api.put("/api/config", cfg);
      const fresh = await api.get("/api/updater/storage");
      storage.download_via = fresh.download_via || "";
      storage.download_iface = fresh.download_iface || "";
      say();
      // The toast reports the OUTCOME, not the save. Writing the setting always succeeds; the setting
      // taking effect is a separate fact, and the two disagree exactly when the operator most needs to
      // know — the ordinary path is blocked, they pick a tunnel to get around it, and every member of
      // the group they picked is down. A group is offered on member KIND, not on member health (the
      // daemon says so where it builds the list), so this state is reachable by clicking alone. The
      // note beside the control already said "not in force" while the toast said, in the success
      // style, "Downloads now go through the router's ordinary path" — true, and the opposite of the
      // news. Choosing nothing is not a failure to report, so only a real choice can warn.
      if (sel.value && !storage.download_iface) {
        // Deliberately the SAME string the note beside it uses. A second wording would be a second
        // translation to keep in step, and the two saying the same thing differently is how a note
        // and a toast drift apart in the first place.
        toast(t("not in force — that connection cannot carry it, downloads take the ordinary path"), "err");
      } else {
        toast(t("Downloads now go through {0}", storage.download_iface || t("the router's ordinary path")), "ok");
      }
    } catch (e) {
      toast(t("Could not save the download path: {0}", (e && e.message) || ""), "err");
      sel.value = storage.download_via || "";
    }
    sel.disabled = false;
  });
  return el("div", { class: "row-between upd-dlpath" },
    el("div", { class: "field" }, el("label", {}, t("Download components through")), sel), note);
}

// installTargetCard answers "where does this land, and is there room" before anything is installed.
//
// The two platforms differ in the way that matters most. KeeneticOS installs add-ons into Entware
// under /opt, which normally lives on an attached USB disk — measured on a live box, 6.7 GB
// free while the router's own storage holds 98 MB. OpenWrt's opkg writes to the overlay, which IS the
// internal flash; filling it can leave the router unbootable. Same button, opposite risk, so the
// daemon reports the real mount (from /proc/self/mounts and statfs) and this card prints it.
//
// Returns immediately with a placeholder and fills in when the daemon answers: a slow storage read
// must not hold up the component rows, which are the reason the page was opened.
function installTargetCard() {
  const card = el("div", { class: "card upd-target" });
  const line = el("div", { class: "upd-target-line" }, el("span", { class: "hint" }, t("reading storage…")));
  card.appendChild(line);
  api.get("/api/updater/storage").then(s => {
    line.innerHTML = "";
    // One line per DISTINCT target. Packages and downloaded engines usually share a disk (on this
    // operator's Keenetic, /opt and /opt/sbin are both the USB stick) and then saying it twice is
    // noise — but the engine directory is an editable setting, so they can genuinely differ, and a
    // single figure would then describe a directory half the installs never touch.
    const rows = s.same_disk
      ? [[t("Installs into"), s.packages]]
      : [[t("Packages install into"), s.packages], [t("Downloaded engines install into"), s.engines]];
    for (const [label, tgt] of rows) {
      if (!tgt) continue;
      const where = el("span", { class: "upd-target-where" },
        label, " ", el("code", {}, tgt.path || "/"),
        tgt.filesystem ? el("span", { class: "upd-target-dev" }, " (" + tgt.filesystem + ")") : null);
      // "external" is the kernel's answer about the DEVICE (sd*/mmcblk*/usb*), not a guess from the
      // path: an operator who moved Entware onto internal storage must not be told it is a USB stick.
      const kind = el("span", { class: "pill " + (tgt.external ? "ok" : "warn") + " pill--dot" },
        el("span", { class: "dot" }),
        tgt.external ? t("attached storage") : t("the router's own flash"));
      const free = el("span", { class: "upd-target-free" }, tgt.free_known
        ? t("{0} free", fmtBytes(tgt.free_bytes))
        : t("free space not measured"));
      line.appendChild(el("div", { class: "row-between" },
        el("div", { class: "upd-target-main" }, where, " ", kind), free));
      // A warning only where it is TRUE: little room on the router's own flash is the case that
      // bricks things. The threshold arrives from the daemon (componentInstallFloor) rather than
      // being written here again: the Diagnostics battery scopes its own verdict to the same number,
      // and when this page held a private copy the two pages gave one disk two answers. No fallback
      // literal — these assets are embedded in the binary that computes the field, so a missing
      // value would mean a build that cannot happen, and a silent 32 MB here is how the copies
      // drifted apart the first time.
      if (!tgt.external && tgt.free_known && tgt.free_bytes < s.install_floor_bytes) {
        const warn = el("div", { class: "upd-target-warn" },
          el("strong", {}, t("Little room on internal flash.")),
          el("span", {}, t("{0} left in {1} — a full overlay can leave the router unable to boot.", fmtBytes(tgt.free_bytes), tgt.path || "/")));
        // "Attach a USB disk" is useless advice on a router that already has one, and the daemon
        // knows: it lists mounted attached storage with more room. Name the disk and the setting
        // that moves engines onto it, rather than restating the problem.
        const room = s.roomier || [];
        if (room.length) {
          warn.appendChild(el("span", {},
            t("There is room on {0} ({1}, {2} free). Point the “{3}” setting at a directory there — the panel installs engines beside it.",
              room[0].path, room[0].filesystem || "?", fmtBytes(room[0].free_bytes), s.engine_setting || "sing-box binary")));
        } else {
          warn.appendChild(el("span", {}, t("Attach a USB disk and move the package tree onto it before installing anything here.")));
        }
        line.appendChild(warn);
      }
    }
    if (s.note) line.appendChild(el("div", { class: "hint upd-target-note" }, s.note));
    line.appendChild(downloadPathRow(s));
    const bits = [];
    if (s.manager && s.manager !== "none") bits.push(t("package manager: {0}", s.manager));
    else bits.push(t("no package manager — components install as downloaded binaries"));
    if ((s.feeds || []).length) bits.push(tn("{0} feed configured|{0} feeds configured", s.feeds.length));
    line.appendChild(el("div", { class: "hint upd-target-pm" }, bits.join(" · ")));
  }).catch(e => {
    // Never silently blank: a card that cannot state the target must say so, because "no answer" and
    // "plenty of room" look identical when the row is empty.
    line.innerHTML = "";
    line.appendChild(el("div", { class: "hint" }, t("Could not read the install target: {0}", e.message)));
  });
  return card;
}

function updVerdict() {
  const rows = [...updRows.values()];
  const n = (st) => rows.filter(r => r.state === st).length;
  // A component that is not installed, or that the system package manager owns, cannot be behind —
  // but it has also not been compared with anything, so it must not be counted as current either.
  // The first draft of this counted them in, and the page announced "Everything is current — 4
  // components checked" over three engines nobody had ever checked. That is the same folding the
  // rest of this audit exists to undo, on the one page where it leaves a router unpatched.
  // sing-box is an optional compatibility add-on. Its absence is not missing work on a
  // native-only router and must not make the Updater verdict look incomplete.
  const optionalAbsent = rows.filter(r => r.state === "absent" && r.optional).length;
  const absent = rows.filter(r => r.state === "absent" && !r.optional).length;
  const managed = rows.filter(r => r.managed).length;
  // An engine whose protocol the kernel carries is not "not installed" — nothing is missing, so
  // counting it among the absent puts a number in the aside that reads as work to do. It is not
  // comparable either: there is no userspace build to compare a version against.
  const kernel = n("kernel");
  // "No update channel" has two causes and only one of them is news. A package catalog that offers no
  // WayHop package is a repository the operator can add. A build whose release list is not published
  // — this one, private repo — will answer that way on every load until the repository opens, so a
  // yellow headline about it is a permanent warning about nothing, which is how a page teaches people
  // to ignore it. The build case joins the aside, as the fact it is; the catalog case keeps its
  // headline below.
  const buildNoChannel = rows.filter(r => r.state === "channel_missing" && r.noChannelBuild).length;
  const channel = n("channel_missing") - buildNoChannel;
  const aside = [];
  if (absent) aside.push(t("{0} not installed", absent));
  if (kernel) aside.push(t("{0} carried by the kernel", kernel));
  if (managed) aside.push(t("{0} owned by the package manager", managed));
  if (buildNoChannel) aside.push(t("WayHop does not self-update in this build"));
  // Built AFTER every aside is collected. It used to be built above the channel line, so the one
  // aside added later appeared in exactly one of the nine headlines below.
  if (channel) aside.push(t("{0} without an update channel", channel));
  const asideText = aside.length ? " · " + aside.join(" · ") : "";

  const behind = n("behind"), unchecked = n("unchecked"), undec = n("undecidable"), err = n("error"), ahead = n("ahead");
  // buildNoChannel is subtracted here too: a build with no release list was not compared with
  // anything. Leaving it in produced "Everything is current · 1 component checked" over a row whose
  // own text says nothing was checked — the precise folding the rest of this function undoes.
  const comparable = rows.length - absent - optionalAbsent - kernel - channel - buildNoChannel;
  // An install the router REFUSED is invisible to every count above: the states describe a version
  // comparison, and an engine that failed to install is simply "not installed", which the aside
  // already reports as an ordinary fact. So the AX3000T's page led with "Everything is current · 1
  // component checked · 2 not installed" while one of those two was not installed because the
  // install had just failed on free space. Nothing regressed there and it is not a reason to shout —
  // but a green all-clear over a failure is a report of success that did not happen, which is the
  // one thing this verdict exists to stop.
  const failed = rows.filter(r => r.failed).length;
  const failText = failed === 1 ? t("1 install failed") : t("{0} installs failed", failed);
  if (behind) {
    return { level: "err", word: t("{0} behind", behind),
      sub: t("of {0} that can be compared", comparable) + asideText + (failed ? " · " + failText : "") };
  }
  // Ahead of the remaining branches, so a failure can never be hidden behind a quieter headline;
  // behind() is the only thing that outranks it, and it carries the failure in its sub-line above.
  // The sub-line reports only what actually settled — `comparable` counts rows that COULD be
  // compared, including the ones nobody has checked, and this branch runs before the checks that
  // would otherwise have caught them.
  if (failed) {
    const cur = n("current");
    const rest = [];
    if (cur) rest.push(t("{0} checked and current", cur));
    if (unchecked) rest.push(t("{0} not checked yet", unchecked));
    if (undec) rest.push(t("{0} cannot be compared", undec));
    if (err) rest.push(t("{0} could not be checked", err));
    return { level: "warn", word: failText,
      sub: (rest.length ? rest.join(" · ") : t("nothing else was compared")) + asideText };
  }
  if (err) {
    return { level: "warn", word: t("{0} could not be checked", err),
      sub: t("nothing is claimed about those") + asideText };
  }
  if (channel) {
    return { level: "warn", word: t("{0} without an update channel", channel),
      sub: t("the installed package is not offered by any configured repository") +
        (managed ? " · " + t("{0} owned by the package manager", managed) : "") };
  }
  if (unchecked) {
    // Never "everything current" while something has not been looked at.
    return { level: "muted", word: t("{0} not checked yet", unchecked),
      sub: (comparable - unchecked - undec > 0
        ? t("{0} checked and current", comparable - unchecked - undec)
        : t("run the sweep to find out")) + asideText };
  }
  if (undec) {
    return { level: "warn", word: t("{0} cannot be compared", undec),
      sub: t("their releases carry a rolling tag, not a version") + asideText };
  }
  if (ahead) {
    return { level: "muted", word: t("{0} newer than the package catalog", ahead),
      sub: t("no downgrade will be offered") + asideText };
  }
  if (!comparable) {
    return { level: "muted", word: t("Nothing to compare"),
      sub: (aside.length ? aside.join(" · ") : t("no components are installed")) };
  }
  return { level: "ok", word: t("Everything is current"),
    sub: (comparable === 1 ? t("1 component checked") : t("{0} components checked", comparable)) + asideText };
}

function paintUpdVerdict() {
  const box = document.getElementById("upd-verdict");
  if (!box) return;
  const v = updVerdict();
  box.innerHTML = "";
  box.className = "upd-verdict " + v.level;
  box.appendChild(el("div", { class: "upd-verdict-w" }, v.word));
  box.appendChild(el("div", { class: "upd-verdict-s" }, v.sub));
}


async function updRefreshPackageLists(btn, pmKind) {
  const original = btn.textContent;
  btn.setAttribute("disabled", "true");
  btn.textContent = t("Preparing…");
  try {
    const plan = await api.get("/api/updater/pm/refresh/plan");
    if (plan.blocked || !(plan.argv || []).length) throw new Error(plan.blocked || t("Package refresh is unavailable."));
    const command = plan.argv.join(" ");
    if (!await modalConfirm(t("Run {0}? This refreshes package lists only; it does not install or upgrade anything.", command))) return;
    btn.textContent = t("Refreshing…");
    const result = await api.post("/api/updater/pm/refresh/apply", { argv: plan.argv });
    if (result.partial) {
      toast(// The key is ONE literal on purpose: check-i18n harvests the first string after tn(, so a key
      // built by concatenation is harvested truncated — it demanded the singular half as its own key
      // and reported the real one as untranslated.
      tn("{0} package list updated by {1}; some repositories failed — check their configuration.|{0} package lists updated by {1}; some repositories failed — check their configuration.", result.updated_sources || "?", pmKind), "info");
    } else {
      toast(t("{0} package lists refreshed", pmKind), "ok");
    }
    route();
  } catch (err) {
    toast(err.message, "err");
  } finally {
    if (btn.isConnected) {
      btn.removeAttribute("disabled");
      btn.textContent = original;
    }
  }
}

// updSweep checks every component at once. Concurrency is what makes one button worth having: eight
// sequential GitHub round-trips on a router is most of a minute.
async function updSweep(btn) {
  const label = btn ? btn.textContent : "";
  if (btn) { btn.setAttribute("disabled", "true"); btn.textContent = t("Checking…"); }
  // Both collections: the button says all, so it checks all. The verdict still reads updRows only.
  const jobs = [...updRows.values(), ...updAdvRows.values()].filter(r => r.check);
  let done = 0;
  await Promise.all(jobs.map(async r => {
    try { await r.check(true); } catch (_) { /* the row records its own error state */ }
    done++;
    if (btn) btn.textContent = t("Checking… {0}/{1}", done, jobs.length);
  }));
  paintUpdVerdict();
  if (btn) { btn.removeAttribute("disabled"); btn.textContent = label || t("Check updates"); }
}

// updStatePill turns a row's state into the one visual the table is read for.
// The id the error pill points its aria-describedby at. One row, one panel, so a constant is enough
// and the relationship survives a re-render.
const UPD_SELF_ERR_ID = "upd-self-error-detail";

// updSelfErrorDetails renders WHY the self-update check failed, reachable by mouse, keyboard AND
// touch. A native <details> is focusable and tappable without any script; the previous design put
// the whole exception in a `title`, which a phone never shows.
//
// Every string here comes from the daemon's redacted attempt list — source kind, host reduced to
// scheme+host, category, duration — so nothing that reaches this panel can carry the credential an
// operator put in a mirror prefix.
function updSelfErrorDetails(s) {
  const attempts = Array.isArray(s.attempts) ? s.attempts : [];
  const det = el("details", { class: "upd-err-det", id: UPD_SELF_ERR_ID });
  det.appendChild(el("summary", {}, attempts.length
    ? tn("{0} source tried — what happened|{0} sources tried — what happened", attempts.length)
    : t("What happened")));
  const body = el("div", { class: "upd-err-body" });
  for (const a of attempts) {
    const meta = [a.category, (a.ms || 0) + " ms", a.status ? "HTTP " + a.status : ""].filter(Boolean).join(" · ");
    body.appendChild(el("div", { class: "upd-err-att" },
      el("span", { class: "upd-err-src" }, a.source === "direct" ? t("direct") : t("mirror")),
      el("code", { class: "upd-err-host" }, a.host || "—"),
      el("span", { class: "upd-err-meta" }, meta),
      a.detail ? el("div", { class: "upd-err-why" }, a.detail) : null));
  }
  if (!attempts.length && s.error) body.appendChild(el("div", { class: "upd-err-why" }, s.error));
  body.appendChild(el("button", {
    class: "btn btn-sm upd-err-copy",
    onclick: () => copyText(updSelfErrorReport(s)),
  }, t("Copy report")));
  det.appendChild(body);
  return det;
}

// updSelfErrorReport is the plain-text form an operator can paste somewhere. It is built from the
// same redacted fields the panel shows, so copying cannot widen what was disclosed.
function updSelfErrorReport(s) {
  const lines = ["WayHop self-update check failed", s.error_summary || s.error || ""];
  for (const a of (s.attempts || [])) {
    lines.push([
      "  " + (a.source === "direct" ? "direct" : "mirror"),
      a.host || "-",
      a.category || "-",
      (a.ms || 0) + "ms",
      a.status ? "HTTP " + a.status : "",
      a.detail || "",
    ].filter(Boolean).join("  "));
  }
  return lines.filter(Boolean).join("\n");
}

function updStatePill(state, note) {
  switch (state) {
    case "behind": return el("span", { class: "badge badge-ok" }, note || t("update available"));
    case "current": return el("span", { class: "pill ok pill--dot" }, el("span", { class: "dot" }), t("up to date"));  // "current" here means the version is up to date, which is a different sentence from the
    // failover role of the same English word; one key for both made nine translators pick a
    // side and half of them get one of the two screens wrong.
    case "undecidable": return el("span", { class: "pill warn", "data-version-undecided": "1" }, t("cannot compare versions"));
    case "channel_missing": return el("span", { class: "pill warn" }, t("no update channel"));
    case "ahead": return el("span", { class: "pill muted" }, t("newer than catalog"));
    // A pill is a chip for one word of state, and this one used to be handed whatever the check
    // failed with — on a real router `Get "https://mirror.ghproxy.com/https://api.gi…"`, six lines
    // tall inside a 225px chip, kept readable only by a `title`. A title is a hover affordance, which
    // is no affordance at all on a phone, and this was the panel's only diagnostic for a failed
    // check. The caller now passes a short label and puts the per-source detail in a <details> below,
    // which is focusable, tappable and wraps.
    case "error": return el("span", { class: "pill err upd-err" }, note || t("check failed"));
    case "managed": return el("span", { class: "pill muted" }, el("span", { class: "dot" }), note || t("managed by the system"));
    case "absent": return el("span", { class: "pill muted" }, el("span", { class: "dot" }), t("not installed"));
    // Not "not installed": the protocol this engine provides is already carried, by the kernel, and
    // saying a component is missing when nothing is missing sends the operator looking for a fix.
    case "kernel": return el("span", { class: "pill ok pill--dot" }, el("span", { class: "dot" }), t("in the kernel"));
    default: return el("span", { class: "pill muted upd-unchecked" }, t("not checked"));
  }
}
const ENGINE_ROLE_HINT = { "core": "core", "kernel-plugin": "kernel plugin", "socks-plugin": "SOCKS plugin", "standalone": "standalone core" };

// updItem builds the shared shell: one grid row plus a full-width detail area beneath it for notes,
// errors and the source-build version picker. Returns the pieces the callers fill in.
function updItem(id) {
  const item = el("div", { class: "upd-item", "data-upd": id });
  const inst = el("span", { class: "upd-inst" }, "—");
  const latest = el("span", { class: "upd-latest" }, "—");
  const state = el("span", { class: "upd-state" }, updStatePill("unchecked"));
  const acts = el("span", { class: "upd-acts" });
  const name = el("span", { class: "upd-name" });
  item.appendChild(el("div", { class: "upd-row" }, name, inst, latest, state, acts));
  const vbox = el("div", { class: "vbox upd-detail" });
  item.appendChild(vbox);
  return { item, name, inst, latest, state, acts, vbox };
}

// updRowErr gives a row's failure ONE owner: find-or-create a single node in the detail area and
// write to it, rather than appending another copy.
//
// Two paths report the same install failure and both used to append. The daemon persists the reason
// (server/updater.go setUpdErr) so every render prints it, and installVersion's catch appends its
// own — so the AX3000T's olcRTC row carried the same 180-character sentence twice, and a second
// failed retry would have made it three. Appending is also what made repeat clicks stack: nothing
// ever removed the previous one. Passing "" clears the line, which is what a row that no longer has
// a failure needs.
function updRowErr(vbox, text) {
  if (!vbox) return null;
  let node = vbox.querySelector(".upd-lasterr");
  if (!text) { if (node) node.remove(); return null; }
  if (!node) {
    node = el("div", { class: "hint upd-err upd-lasterr" });
    vbox.appendChild(node);
  }
  node.textContent = text;
  return node;
}

// engineStateFrom decides what a version reply actually established.
//
// The two traps it exists for. An engine with no comparable release (a source-only build, or a reply
// with no latest at all) is NOT current — nothing was compared. And a nightly engine whose id is a
// build DATE cannot be called current on an equal date: a same-day rebuild shares the date and has a
// different commit, so equality proves nothing while a strictly-older date proves "behind".
function engineStateFrom(v) {
  const norm = (s) => String(s || "").replace(/^v/i, "");
  const inst = norm(v.installed);
  const latest = norm(v.latest_version || v.latest);
  if (!inst) return { state: latest ? "absent" : "unchecked", latest: latest || "" };
  if (!latest) return { state: "undecidable", latest: "", note: t("no comparable release") };
  if (v.latest_version) {
    if (inst < norm(v.latest_version)) return { state: "behind", latest, note: t("newer build available") };
    return { state: "undecidable", latest, note: t("same build date — equality proves nothing") };
  }
  return inst === latest ? { state: "current", latest } : { state: "behind", latest };
}

// selfUpdateRow — WayHop's own row. Keeps every control the card had: Update now, the auto-update
// switch, and the package-manager explanation when the binary is not ours to swap.
// updSelfNoChannel remembers ONE answer for the session: that this build has no release list to
// update from. Nothing else is cached here.
//
// The check runs on every render of this page, and the daemon answers it by calling api.github.com.
// For a build whose repository is private that answer is a property of the BUILD — 404, every time —
// so re-asking on each visit buys nothing and costs a round trip; on a router where GitHub is
// unreachable it costs the full 20-second timeout before the row can say anything. A live comparison
// (a real version, an error, a package-manager verdict) is never cached: those change under the
// operator's feet and a stale one would be a lie. "Check updates" always asks again.
let updSelfNoChannel = null;

function selfUpdateRow() {
  const p = updItem("wayhop");
  p.name.appendChild(el("span", { class: "upd-n" }, "WayHop"));
  p.name.appendChild(el("span", { class: "upd-r" }, t("the panel itself")));
  const rec = { id: "wayhop", state: "unchecked", managed: false };
  rec.check = async (force) => {
    try {
      const s = (!force && updSelfNoChannel) ? updSelfNoChannel : await api.get("/api/updater/self");
      if (s.no_channel) updSelfNoChannel = s; else updSelfNoChannel = null;
      const managed = !!s.native_managed;
      // Same fail-closed rule as the engine rows: SelfUpdate refuses when it cannot verify whether the
      // package manager owns the running binary, so an unverified answer must not offer "Update now".
      const unknownOwner = !!s.ownership_unknown;
      const pkg = s.package_status || {};
      rec.managed = managed;
      if (managed) {
        p.inst.textContent = s.current ? "v" + s.current : (pkg.installed_version || "—");
        p.latest.textContent = pkg.latest_version || "—";
        rec.state = ({
          behind: "behind", current: "current", ahead: "ahead",
          catalog_error: "error", channel_missing: "channel_missing",
        })[pkg.state] || "undecidable";
        p.state.innerHTML = "";
        p.state.appendChild(updStatePill(rec.state,
          rec.state === "behind" ? t("update → {0}", pkg.latest_version || "?") : ""));
        p.state.appendChild(updStatePill("managed", t("managed by {0}", s.package_manager || "the system")));
        p.acts.innerHTML = "";
        p.vbox.innerHTML = "";
        p.vbox.appendChild(el("div", { class: "hint upd-pkg-note" },
          t("Installed as {0} package {1}{2}.", s.package_manager || "system", pkg.package || "wayhop",
            pkg.installed_version ? " · " + pkg.installed_version : "")));
        if (pkg.state === "catalog_error") {
          p.vbox.appendChild(el("div", { class: "upd-remedy" },
            el("strong", {}, t("Package lists are unavailable.")),
            el("span", {}, t("Use “Refresh package lists” above, then check again."))));
        } else if (pkg.state === "channel_missing") {
          p.vbox.appendChild(el("div", { class: "upd-remedy" },
            el("strong", {}, t("No configured repository offers WayHop.")),
            el("span", {}, t("This package was installed locally. WayHop will not overwrite a package-owned binary or pretend that a no-op is an update."))));
        } else if (pkg.state === "ahead") {
          p.vbox.appendChild(el("div", { class: "hint" },
            t("The installed package is newer than the package catalog. No downgrade is offered.")));
        } else if (pkg.state === "behind") {
          p.vbox.appendChild(el("div", { class: "upd-remedy" },
            el("strong", {}, t("A package update is available.")),
            el("span", {}, t("WayHop cannot safely replace its own package from inside the running service yet. Use the package manager over SSH for this update."))));
        }
        p.vbox.appendChild(el("div", { class: "hint upd-auto-note" },
          t("Automatic WayHop updates are controlled by the package manager for this installation.")));
        return;
      }
      // A build with nowhere to update FROM is not a failed check. The daemon reports no_channel when
      // every source answered 404 — what a private repository (this build's, for now) and one with no
      // releases both answer — and the row then states that fact instead of showing a red "refused by
      // the server" pill with a three-source failure report under it, which had operators chasing a
      // network fault that did not exist.
      if (s.no_channel) {
        rec.state = "channel_missing";
        // Tells updVerdict WHICH channel_missing this is: the build's, not a package catalog's. The
        // two need opposite treatment — see the verdict's comment.
        rec.noChannelBuild = true;
        p.inst.textContent = s.current ? "v" + s.current : "—";
        p.latest.textContent = "—";
        p.state.innerHTML = "";
        p.state.appendChild(updStatePill("channel_missing", t("does not self-update")));
        p.acts.innerHTML = "";
        p.vbox.innerHTML = "";
        p.vbox.appendChild(el("div", { class: "hint" },
          t("This build has no update channel: {0}. Nothing is wrong with the router — WayHop is updated by reinstalling it.", s.no_channel_reason || t("the release list is not published"))));
        return;
      }
      const undecidable = !s.error && s.version_comparable === false;
      p.inst.textContent = s.current ? "v" + s.current : "—";
      p.latest.textContent = s.latest || "—";
      rec.state = s.error ? "error" : undecidable ? "undecidable"
        : s.update_available ? "behind" : "current";
      p.state.innerHTML = "";
      // The pill gets a LABEL, never the exception: error_summary is the daemon's own short reading
      // ("name not resolved", "refused by the server"), and it falls back to a generic phrase rather
      // than to the raw message.
      const errLabel = s.error ? (s.error_summary || t("Check failed")) : "";
      const errPill = updStatePill(rec.state,
        rec.state === "behind" ? t("update → {0}", s.latest || "?") : errLabel);
      if (s.error) errPill.setAttribute("aria-describedby", UPD_SELF_ERR_ID);
      p.state.appendChild(errPill);
      if (managed) {
        p.state.appendChild(updStatePill("managed", t("managed by {0}", s.package_manager || "the system")));
      }
      p.acts.innerHTML = "";
      if (s.update_available && !managed && !unknownOwner) {
        p.acts.appendChild(el("button", { class: "btn btn-sm btn-primary", onclick: ev => selfUpdate(ev.target) }, "Update now"));
      }
      p.vbox.innerHTML = "";
      // What it costs and whether it fits, while the choice is still open — the same note the
      // engine rows get, now that /api/updater/self/fit can answer for the daemon itself. On a
      // small-flash router the refusal is the routine outcome, not the edge case: measured on the
      // operator's AX3000T, ~27 MiB needed against 13 MiB free, and until now that sentence could
      // only arrive after pressing a button that was always offered.
      if (s.update_available && !managed && !unknownOwner) {
        p.vbox.appendChild(installCostNote({ id: "self", name: "WayHop" }, s.latest || ""));
      }
      // Cleared first, above, so a repeated "Check all" replaces this panel instead of stacking a
      // second copy of it under the row.
      if (s.error) p.vbox.appendChild(updSelfErrorDetails(s));
      if (undecidable) {
        p.vbox.appendChild(el("div", { class: "hint" },
          t("The newest release is tagged “{0}”, which carries no version number to compare with.", s.latest || "?")));
      }
      if (unknownOwner && !managed) {
        p.vbox.appendChild(el("div", { class: "hint" },
          t("Could not check whether {0} owns the running binary, so self-update is held back — the install path refuses in this state too. Retry in a moment.", s.package_manager || "the package manager")));
      }
      if (managed) {
        p.vbox.appendChild(el("div", { class: "hint" },
          t("Installed by the system package manager. Update it with {0} over SSH — the panel won't touch it.", s.package_manager || "opkg/apk")));
      }
      const tog = switchEl(s.auto_update, tel => selfAutoToggle(tel), "Auto-update WayHop");
      p.vbox.appendChild(el("div", { class: "row-between upd-auto" },
        el("div", { class: "hint" }, "Auto-update: install new WayHop releases automatically (daily check) and restart"),
        tog));
    } catch (e) {
      rec.state = "error";
      p.state.innerHTML = "";
      p.vbox.innerHTML = "";
      const pill = updStatePill("error", t("Check failed"));
      pill.setAttribute("aria-describedby", UPD_SELF_ERR_ID);
      p.state.appendChild(pill);
      // The daemon was unreachable, so there are no attempts to show — the transport error is the
      // whole story, and it still goes in the reachable panel rather than a hover-only title.
      p.vbox.appendChild(updSelfErrorDetails({ error: e.message }));
    }
  };
  updRows.set("wayhop", rec);
  // Runs immediately, and without force: the page is opened to see this row, but a build already
  // known to have no update channel answers from updSelfNoChannel instead of GitHub.
  rec.check().then(paintUpdVerdict);
  return p.item;
}

// engineRow — one engine, compressed from a card. Advanced (catalog-only) engines are rendered the
// same way but stay out of updRows, so the verdict never counts binaries this router will never run.
// pmDelegation renders the native package-manager actions for an engine the PM owns.
//
// Three things the page could not do before: install, roll back and remove a packaged engine. The
// panel already shipped the code for all three (internal/pm) and reached none of it, so it printed a
// paragraph telling the operator to open an SSH session instead.
//
// The shape follows the UCI writer rather than the old one-click buttons: nothing runs until the
// exact command has been shown. A click asks the daemon what it WOULD do, the command appears, and a
// second click runs that same command — the server re-plans and refuses if it changed in between, so
// the confirmation is real rather than decorative.
//
// A blocked plan renders its CHECKS. "Why can't I?" used to be answered with prose; it is now the
// list of preconditions with the one that failed marked, which is the same list the daemon used.
//
// mode picks which actions belong on this row:
//
//	"owned"   — package-manager-owned, with a newer build in the feed: update, roll back, remove
//	"managed" — package-manager-owned, nothing newer offered: roll back and remove, no update
//	"install" — the engine is NOT there yet, which is a different row in a different state and shares
//	            only the ask-then-run discipline
// pmSpaceNote is the disk arithmetic behind the plan, shown whether or not it changed anything.
//
// Measured on the AX3000T: /overlay has 20.2 MiB free and the sing-box the feed offers unpacks to
// 42.4 MiB, so the ordinary one-command upgrade cannot work there by any amount of retrying. A plan
// that quietly picks the two-command path instead is not much better than one that fails — the
// operator is the one whose routing stops between those commands — so the figures that forced the
// choice are shown with the commands rather than behind them.
function pmSpaceNote(sp, nsteps) {
  const line = t("{0} needed, {1} free in {2}.", fmtBytes(sp.need_bytes), fmtBytes(sp.avail_bytes), sp.dir || "?");
  if (nsteps < 2) return el("div", { class: "hint" }, line);
  return el("div", { class: "upd-target-warn" },
    el("strong", {}, t("Not enough room for both builds.")),
    el("span", {}, line + " " +
      t("The installed build is removed first to make room, then {0} is installed.",
        sp.target_version || "the new build")));
}

function pmDelegation(e, pmKind, mode) {
  const box = el("div", { class: "pm-deleg" });
  const status = el("div", { class: "hint" });
  const preview = el("div", { class: "pm-cmd" });
  const acts = el("div", { class: "acts" });
  const detail = el("div", { class: "pm-checks" });
  box.appendChild(acts);
  box.appendChild(preview);
  box.appendChild(detail);
  box.appendChild(status);

  const url = (path) => "/api/updater/" + encodeURIComponent(e.id) + "/pm/" + path;
  const clear = () => { preview.innerHTML = ""; detail.innerHTML = ""; status.textContent = ""; };

  // Render the preconditions. Passed ones are listed too: knowing WHAT was verified is half of
  // trusting the answer, and a list of only failures reads as if nothing else was looked at.
  const showChecks = (checks) => {
    detail.innerHTML = "";
    if (!checks || !checks.length) return;
    const d = el("details", { class: "pm-why" }, el("summary", { class: "hint" }, t("What was checked")));
    const ul = el("div", { class: "vbox" });
    for (const c of checks) {
      // A note is printed whatever the verdict. This used to drop them on passing checks, and it had
      // to: the daemon stored each check's FAILURE text even when the check passed, so "✓ package
      // manager present — no opkg or apk on this system" was one render away. The daemon now keeps a
      // note only when it is true, which frees the one that matters — on a name resolved through a
      // virtual provides, the sentence saying the command names `sing-box-go` and not the `sing-box`
      // the operator asked for.
      ul.appendChild(el("div", { class: "hint" + (c.ok ? "" : " upd-err") },
        (c.ok ? "✓ " : "✗ ") + c.name + (c.note ? " — " + c.note : "")));
    }
    d.appendChild(ul);
    detail.appendChild(d);
  };

  // Ask what would happen. Runs nothing on the router.
  const plan = async (action, version) => {
    clear();
    status.textContent = t("Checking what would run…");
    let p;
    try {
      p = await api.get(url("plan") + "?action=" + encodeURIComponent(action) +
        (version ? "&version=" + encodeURIComponent(version) : ""));
    } catch (err) {
      status.textContent = err.message;
      return null;
    }
    showChecks(p.checks);
    if (p.blocked) {
      status.textContent = "";
      preview.appendChild(el("div", { class: "hint upd-err" }, t("Not possible here:") + " " + p.blocked));
      return null;
    }
    status.textContent = "";
    // A plan can be more than one command. Two is not a longer version of one: the first takes the
    // installed build off the disk so the second has room to write the new one, and between them the
    // router has no core at all. They are listed in order, with the arithmetic that forced the
    // choice under them — the operator is agreeing to both, and to the window between them.
    const steps = (p.steps && p.steps.length) ? p.steps : [p.argv || []];
    preview.appendChild(el("div", { class: "hint" },
      steps.length > 1 ? t("This will run, in order:") : t("This will run:")));
    for (const st of steps) preview.appendChild(el("code", { class: "pm-argv" }, (st || []).join(" ")));
    if (p.space && p.space.measured) preview.appendChild(pmSpaceNote(p.space, steps.length));
    // The command is not the effect. Measured on the AX3000T: `apk del sing-box` reads as one
    // package and removes two, taking kmod-inet-diag with it. A preview that shows only the command
    // asks for consent to something the operator cannot see.
    if (p.collateral && p.collateral.length) {
      preview.appendChild(el("div", { class: "hint upd-err" },
        t("This also removes:") + " " + p.collateral.join(", ")));
    }
    if (p.effect) {
      preview.appendChild(el("details", { class: "pm-why" },
        el("summary", { class: "hint" }, t("What it would do")),
        el("pre", { class: "pm-argv pm-effect" }, p.effect)));
    }
    const go = el("button", { class: "btn btn-sm btn-primary" }, t("Run it"));
    go.addEventListener("click", async () => {
      go.setAttribute("disabled", "true");
      status.textContent = t("Running…");
      // Removing the package deletes the binary the router is running on, so the daemon refuses once
      // and says what the removal costs. That is a question, not a dead end: ask it, and send the
      // answer back with the SAME command — the server re-plans either way, so a yes here approves
      // the stop, never a different operation.
      const run = async (stop) => api.post(url("apply"),
        { action, version: version || "", argv: p.argv, steps: p.steps || [],
          ...(stop ? { stop: true } : {}) });
      try {
        let r;
        try {
          r = await run(false);
        } catch (err) {
          if (!(err.data && err.data.needs_stop)) throw err;
          if (!await modalConfirm(err.message)) {
            status.textContent = "";
            go.removeAttribute("disabled");
            return;
          }
          r = await run(true);
        }
        status.textContent = (r && r.output ? String(r.output).trim().slice(0, 300) : t("Done."));
        // The SUCCESS outcome needs exactly the treatment the comment below prescribes, and did not get
        // it: it was written into `status` and route() rebuilds the page and takes that line with it in
        // the same tick. Measured through the panel on a live router — a successful
        // `apk add dnscrypt-proxy` and the `apk del` that undid it BOTH left no toast and no line, so
        // the package changed and the page said nothing at all. The failure path below was toasted for
        // this exact reason; the path that runs every time was not.
        {
          const cmd = (p.argv || []).join(" ");
          const last = r && r.output
            ? String(r.output).trim().split(/\r?\n/).filter(Boolean).pop() || ""
            : "";
          toast(cmd + (last ? " — " + last.slice(0, 140) : " — " + t("Done.")), "ok");
        }
        // The package changing and the router working are two different outcomes. The daemon reloads
        // the core onto the binary it just wrote and reports `reload_error` when it does not come
        // back — and showing only the package manager's cheerful line would leave the operator with
        // "OK: 1 package upgraded" while the datapath is down. sing-box 1.13 removed the `wireguard`
        // outbound, so an upgrade across that line refusing an older config is the ordinary case.
        //
        // It goes out as a TOAST, not only into this line: route() below rebuilds the page and takes
        // the delegation box with it, so anything written here is gone within the tick. Toasts live
        // outside the page container and survive the re-render, which is why every other outcome in
        // this file is reported with one.
        if (r && r.reload_error) {
          status.className = "hint upd-err";
          status.textContent = t("The core did not restart:") + " " + r.reload_error;
          toast(t("The core did not restart:") + " " + r.reload_error, "err");
        } else {
          status.className = "hint";
        }
        // The daemon re-read the package database after the command and found the installed build
        // unchanged. That is the exact shape of the defect this path was fixed for — `apk add` on an
        // installed package prints OK and moves nothing — so it is reported as loudly as a failure
        // rather than left to be spotted in a version column.
        if (r && r.verify_error) toast(r.verify_error, "err");
        // Same half-finished job on the package-manager path: opkg/apk wrote the files, the applied
        // plan still does not know about them.
        if (mode === "install") { updJustInstalled = e.id; updJustConverged = !!r.converged; updJustDemo = !!r.demo; }
        route();
      } catch (err) {
        status.textContent = err.message;
        go.removeAttribute("disabled");
      }
    });
    preview.appendChild(go);
    return p;
  };

  const act = (label, action, aria) => {
    const b = el("button", { class: "btn btn-sm", "aria-label": aria || (label + " " + e.name) }, label);
    b.addEventListener("click", () => plan(action, ""));
    return b;
  };

  // The absent engine gets one action and stops here. Update, Remove and Roll back all name a package
  // the manager already owns; none of them mean anything for a binary that is not there, and offering
  // them would produce three refusals. The manager is named on the button because the row ALSO carries
  // a "Install selected" that downloads a release from GitHub — same word, different source, and the
  // operator is choosing between them.
  if (mode === "install") {
    // Ask BEFORE offering. The daemon already answers whether this package exists in the configured
    // feeds — PlanPM does the candidate lookup and the virtual-name resolution — and the page drew the
    // button anyway, so the check landed after the click. Measured on a live Keenetic:
    // "Install with opkg" sat there until pressed, then answered "opkg has no package called
    // 'sing-box' and nothing provides it". Of the seven engines this panel knows, the AX3000T's feed
    // carries two; the rest are buttons that cannot work.
    //
    // Nothing is drawn until the answer arrives, rather than a button that might be withdrawn: a
    // control appearing and vanishing under the cursor is its own defect.
    const pending = el("span", { class: "hint" }, t("checking the feed…"));
    acts.appendChild(pending);
    api.get(url("plan") + "?action=install").then(p => {
      pending.remove();
      if (p && p.blocked) {
        // The reason, in place of the control — with the same evidence the click used to reveal.
        // showChecks owns `detail`, so the sentence goes above it in `preview`, exactly as the
        // post-click refusal already renders it.
        preview.appendChild(el("div", { class: "hint upd-err" }, t("Not possible here:") + " " + p.blocked));
        showChecks(p.checks);
        return;
      }
      acts.appendChild(act(t("Install with {0}", pmKind || "the package manager"), "install",
        t("Install {0} with {1}", e.name, pmKind || "the package manager")));
    }).catch(err => {
      // The feed could not be asked. Offering the button is right here: refusing on a failed LOOKUP
      // would hide a working install behind a transient package-manager lock.
      pending.remove();
      acts.appendChild(act(t("Install with {0}", pmKind || "the package manager"), "install",
        t("Install {0} with {1}", e.name, pmKind || "the package manager")));
      detail.appendChild(el("div", { class: "hint" },
        t("The feed could not be checked first ({0}), so this may still refuse.", (err && err.message) || "")));
    });
    return box;
  }

  // "owned" is the package-manager-owned engine with a newer build in the feed; "managed" is the
  // same engine with nothing to update to. Both may be removed and rolled back — those actions are
  // about the build that is installed, not about the one the feed offers — and until this line
  // existed neither was reachable from anywhere: the only call sites passed "install" and "update",
  // and "update" returned here, one statement before the Remove button was appended. The daemon has
  // carried a tested `apk del` plan, its collateral list and its stop gate the whole time.
  if (mode === "owned") acts.appendChild(act(t("Update"), "upgrade"));
  acts.appendChild(act(t("Remove"), "remove"));
  // The package-manager path shows the exact command before it runs anything, which answers "what
  // will happen to the FILES" and says nothing about what will happen to the operator's routing. The
  // panel-installed path already names the dependents in its confirmation (see removeEngine); an
  // engine that opkg owns is removed just as thoroughly, so the same warning belongs here.
  const removeUsedBy = e.used_by || [];
  if (removeUsedBy.length) {
    detail.appendChild(el("div", { class: "hint upd-usage" },
      t("Removing it stops: {0}.", removeUsedBy.join(", "))));
  }

  // Rolling back needs a build to roll back TO, and the list has to come from the package manager's
  // own feed rather than from GitHub: those are two different sources, and offering a tag the feed
  // does not carry would fail at the package manager after the operator confirmed it.
  const rb = el("button", { class: "btn btn-sm", "aria-label": t("Roll back") + " " + e.name }, t("Roll back"));
  rb.addEventListener("click", async () => {
    clear();
    status.textContent = t("Asking {0} what builds it has…", pmKind || "the package manager");
    let r;
    try { r = await api.get(url("candidates")); } catch (err) { status.textContent = err.message; return; }
    if (r.blocked) { showChecks(r.checks); status.textContent = ""; preview.appendChild(el("div", { class: "hint upd-err" }, t("Not possible here:") + " " + r.blocked)); return; }
    // Whether a named build can be installed at all is a property of the box, and asking it here is
    // the difference between declining and dangling. This used to list the feed's builds on an opkg
    // router, let the operator pick one, and answer only then that opkg cannot install a named
    // version — the refusal arriving after the choice, which is the shape of a menu with nothing
    // behind it. The Keenetic is an opkg router.
    if (r.can_pin === false) {
      status.textContent = "";
      preview.appendChild(el("div", { class: "hint upd-err" },
        t("Not possible here:") + " " + (r.cannot_pin_reason || "")));
      return;
    }
    // Rolling back TO the build already installed is not a rollback. Measured on the AX3000T:
    // `apk list sing-box` returns two lines for one version — the installed one and the same one
    // again — so the picker would have offered a single option that changes nothing, and the
    // command behind it (`apk add sing-box=1.12.17-r1`) would have looked like an action.
    const list = (r.candidates || []).filter((c) => c.Available && !c.Installed);
    if (!list.length) { status.textContent = t("This feed offers no other build to roll back to."); return; }
    status.textContent = "";
    const sel = el("select", {}, ...list.map((c) => el("option", { value: c.Version },
      c.Version + (c.Installed ? "  (" + t("installed") + ")" : ""))));
    sel.setAttribute("aria-label", t("Version"));
    const pick = el("div", { class: "upd-pick" }, sel,
      el("button", { class: "btn btn-sm" }, t("Show the command")));
    pick.lastChild.addEventListener("click", () => plan("rollback", sel.value));
    preview.appendChild(pick);
  });
  acts.appendChild(rb);

  return box;
}

// updJustInstalled carries ONE fact across the re-render that follows an install: which engine it
// was. Consumed by the next engineRow that matches, then cleared.
//
// It exists because the install is only half of the job and the page used to end at the half. A core
// is installed because something needed it — and installing the binary does not put those
// connections into the datapath: the applied plan was compiled while the core was absent, so they
// stay dark until the next Apply. The success toast said "sing-box → v1.13.19 (reloaded)" and the
// page re-rendered looking finished, with the operator's VLESS exit still carrying nothing and
// nothing on screen saying why. Nor can the panel infer it later: installing a binary is not a
// profile change, so the "unapplied changes" banner does not appear either.
// The engine whose install just finished, plus what the daemon did about it — the note below the row
// reports the outcome, and "the daemon started it for you" and "nothing runs it yet" are different
// outcomes that used to share one sentence.
let updJustInstalled = null;
let updJustConverged = false;
// Whether the package manager that "installed" it was the demo one, which changes nothing on purpose.
let updJustDemo = false;

// installedNextStep is the line that closes that gap, shown once, on the row that was just
// installed, naming what is waiting.
function installedNextStep(usedBy, converged, demo) {
  // Demo mode's package manager returns the command it WOULD have run and touches nothing, and this
  // block announced "Installed." over it — beside a State column still reading "not installed" and a
  // toast saying nothing was installed. Measured on the demo: apk add sing-box, three statements
  // about one action, one of them false. The block still renders, because suppressing it would leave
  // the whole after-install explanation appearing on no page anywhere (the reason DemoPM exists at
  // all); it just says what happened instead of claiming an install.
  if (demo) {
    return el("div", { class: "upd-remedy" },
      el("strong", {}, t("Nothing was installed — demo mode.")),
      el("span", {}, usedBy.length
        ? t("On a router this is where {0} would be told they run after the next Apply.", usedBy.join(", "))
        : t("On a router this is where the outcome of the install would be reported.")));
  }
  // The daemon starts the core itself when the committed plan expects one, so the ordinary case has
  // no next step at all — it has an outcome. This line used to end with "Open Review & Apply" in
  // every case, and on a live router that was a dead end: installing a binary changes neither
  // profile nor config, so nothing was pending, no Apply control existed, and the sentence pointed at
  // something that was not there. Only a daemon restart fixed it.
  if (converged) {
    return el("div", { class: "upd-remedy" },
      el("strong", {}, t("Installed and running.")),
      el("span", {}, usedBy.length
        ? t("The router was brought back in line with its applied configuration, so {0} are carried again.", usedBy.join(", "))
        : t("The router was brought back in line with its applied configuration.")));
  }
  return el("div", { class: "upd-remedy" },
    el("strong", {}, t("Installed.")),
    el("span", {}, usedBy.length
      ? t("{0} will use it the next time the configuration is applied — the router's current plan was built while this was missing.", usedBy.join(", "))
      : t("Nothing is waiting on it: the applied configuration does not run this engine.")));
}

// componentsToShow picks the rows this router's datapath can actually use, out of the whole catalog.
//
// An operational row carries buttons, and that is the whole constraint. Widening this to every engine
// that PROVIDES a protocol put AmneziaWG back on the page with an install control beside the sentence
// "the userspace build is not needed here" — the exact row scripts/ui-kernel-carried.mjs was written
// after: three true statements that together read as an instruction to fix a working router, on the
// operator's router, while the kernel module was carrying their tunnel. The same applies to a plugin
// opkg or apk owns: the page must not offer to install over the package manager.
//
// The fact those engines carry is not lost — it has no buttons on it. kernelCarriedNote states it as
// prose below the table, which is where "nothing to install for this" belongs.
//
// The catalog engines that stay hidden (mihomo, Xray, standalone Hysteria, dnscrypt-proxy) are hidden
// for a reason that still holds: WayHop's datapath is native tunnels plus sing-box, so installing one
// of those binaries would change no routing. VLESS/Reality, Hysteria2, TUIC and AnyTLS are not
// missing from this list — they ride inside sing-box, which is why its row names them.
//
// The AmneziaWG 3 component is the exception that proves the rule: it gets a row when a connection
// here runs on it (e.awg.needed, the daemon's own path decision), when it is installed and so has
// something to update or remove, or when it would add something the router lacks (e.awg.optional:
// the router's own AmneziaWG is older than amneziawg-go's). That last row says it is optional and
// why, so its Install reads as an offer rather than a fix. Only a router whose own AmneziaWG is
// already the newest generation gets the prose below and no button.
function componentsToShow(engines) {
  return (engines || []).filter(e => e.role === "core" ||
    (e.awg && (e.awg.needed || e.awg.optional || (e.installed || {}).present)));
}

// kernelCarriedNote states what this router already carries itself, without offering to install it.
//
// It answers the question the operator actually has ("where is AmneziaWG?") with the answer that ends
// it ("in your kernel; there is nothing to install"), and it is prose precisely so that no click can
// follow from it. An engine the package manager owns is named the same way: the router has it, and
// this page is not the place it gets changed.
function kernelCarriedNote(engines) {
  const kernel = (engines || []).filter(e => e.carried_by_kernel && !(e.installed || {}).present);
  const managed = (engines || []).filter(e => e.native_managed && !e.carried_by_kernel && e.role !== "core");
  const lines = [];
  if (kernel.length) {
    // The generation goes with the name where the daemon knows it: "carries AmneziaWG" alone once
    // stood over a generation-2 module that cannot carry a 3.x setting.
    const label = e => (PROTO_LABEL[e.provides] || e.provides || e.name) +
      (e.awg && e.awg.builtin && !["none", "unknown"].includes(e.awg.builtin) ? " " + e.awg.builtin : "");
    lines.push(t("This router's kernel carries {0} itself — nothing to install for it.",
      kernel.map(label).join(", ")));
  }
  if (managed.length) {
    lines.push(t("{0} is installed and owned by the package manager — update it there, not here.",
      managed.map(e => e.name || e.id).join(", ")));
  }
  // A kernel path WayHop's installer can take back out: its packages are installed and the installer
  // applies here. The way out sits behind a closed disclosure - nothing is missing on this router.
  const removable = kernel.find(e => e.awg && (e.awg.feed_modes || []).includes("kmod") &&
    (e.awg.packages || []).some(k => k.name === "kmod-amneziawg"));
  // What the connections or netifd have not caught up with yet: the row that would say it is gone.
  const pending = kernel.find(e => e.awg && (e.awg.switching || e.awg.netifd_restart));
  return lines.length ? el("div", { class: "hint upd-carried" }, lines.join(" "),
    pending ? awgPendingBlock(pending.awg) : null,
    removable ? awgFeedRemoval(removable) : null) : null;
}

// PROTO_LABEL is display only: the daemon speaks lowercase proto ids and an operator reads brand
// names. Anything not listed falls back to the id, so a protocol added to the backend appears here
// (as "anytls" rather than not at all) instead of silently vanishing from the list.
const PROTO_LABEL = {
  vless: "VLESS", vmess: "VMess", trojan: "Trojan", shadowsocks: "Shadowsocks",
  hysteria2: "Hysteria2", tuic: "TUIC", anytls: "AnyTLS", socks: "SOCKS", http: "HTTP",
  wireguard: "WireGuard", amneziawg: "AmneziaWG",
};

// usageNote states what in THIS profile depends on the engine — the fact that makes "not installed"
// normal, and the one that decides whether Remove is safe.
//
// The two absences are not the same sentence and must not share one. An engine that is not installed
// and that nothing uses is the router working as designed; an engine that IS installed and that
// nothing uses is 40 MB of flash doing nothing, which is a thing to act on. Saying "nothing uses it"
// for both would leave the second invisible, which is how the unused core stayed on small-flash
// routers nobody could find space on.
function usageNote(usedBy, installed) {
  if (usedBy.length) {
    return el("div", { class: "hint upd-usage" },
      installed
        ? t("In use by: {0}.", usedBy.join(", "))
        : t("Needed by: {0} — those will not work until it is installed.", usedBy.join(", ")));
  }
  return el("div", { class: "hint upd-usage" }, installed
    ? t("Nothing in this profile uses it. Removing it frees the space and changes no routing.")
    : t("Nothing in this profile needs it — this router routes natively, so not installed is the normal state here."));
}

// unlockNote says what installing the engine would ADD, and what the router already carries without
// it. Both halves come from the daemon's own capability probe — the protocol list is never written
// down here, so a router that gains a native path stops being told it needs a core for it.
//
// This replaces one sentence ("install only when a connection type is not supported natively") that
// was true and unusable: it named no protocol, so the operator could not tell whether their case was
// one of them, and an absent sing-box read as something missing rather than as the normal state.
function unlockNote() {
  const box = el("div", { class: "upd-unlock" });
  const line = el("div", { class: "hint" }, t("asking the router what it can carry…"));
  box.appendChild(line);
  api.get("/api/native/capabilities").then(c => {
    const names = (ids) => ids.map(id => PROTO_LABEL[id] || id).join(", ");
    const need = (c.singbox_required || []).slice();
    const native = Object.keys(c.native || {}).filter(k => c.native[k]);
    box.innerHTML = "";
    // The order is deliberate: what the router ALREADY does comes first, because that is the reason
    // "not installed" is normal here, and it is the half the old page never said.
    if (native.length) {
      box.appendChild(el("div", { class: "hint" },
        t("This router already carries {0} natively — those connections need no engine.", names(native))));
    }
    if (need.length) {
      box.appendChild(el("div", { class: "hint" },
        t("Installing it would add: {0}.", names(need))));
    } else {
      box.appendChild(el("div", { class: "hint" },
        t("The router reports no protocol that would need this engine.")));
    }
  }).catch(() => {
    // Degrade to the honest general statement rather than to a protocol list invented client-side.
    line.textContent = t("Install this add-on only when a connection type is not supported by the router natively.");
  });
  return box;
}

// collapsedOffer is the "what would this give me" panel for a router that needs nothing — built on
// FIRST OPEN, not at render.
//
// installCostNote asks the daemon to measure the download, and the daemon answers that by calling
// api.github.com directly (the release metadata must not come from a mirror — it is what a digest is
// checked against). Building it eagerly meant every visit to this page made that call on a router
// whose answer is "you need nothing": on a censored or offline router that is a request that hangs
// for the full 20-second timeout and then renders "Size not measured", once per visit, to fill a
// panel nobody opened. A closed <details> is a question the operator has not asked yet.
function collapsedOffer(e) {
  const det = el("details", { class: "upd-offer" });
  det.appendChild(el("summary", {}, t("What installing it would add")));
  let filled = false;
  // `toggle` fires on open AND on close; the guard makes the fill happen once, so closing and
  // reopening does not stack a second copy of both notes (and a second pair of requests).
  det.addEventListener("toggle", () => {
    if (filled || !det.open) return;
    filled = true;
    det.appendChild(unlockNote());
    det.appendChild(installCostNote(e));
  });
  return det;
}

// installCostNote is the answer to "what does this cost me" while the choice is still open: the
// download, the space it actually needs unpacked, where it lands, and whether it fits.
//
// It asks GET /api/updater/<id>/fit, which runs the SAME predicate the install path enforces. That
// is the point: the refusal used to arrive only after the operator picked a version and pressed
// Install, which on a small-flash router is the routine outcome, not the edge case.
function installCostNote(e, version) {
  const box = el("div", { class: "upd-cost" });
  box.appendChild(el("div", { class: "hint" }, t("measuring the download…")));
  api.get("/api/updater/" + encodeURIComponent(e.id) + "/fit"
    + (version ? "?version=" + encodeURIComponent(version) : "")).then(f => {
    box.innerHTML = "";
    const parts = [
      t("{0} download", fmtBytes(f.download_bytes)),
      // Not the same number: an archive inflates on the way out, and quoting the download size next
      // to a 60 MiB overlay would understate a 34 MiB install by a factor of three.
      t("needs ~{0} free in {1}", fmtBytes(f.need_bytes), f.dir || "?"),
    ];
    if (f.avail_known) parts.push(t("{0} free there", fmtBytes(f.avail_bytes)));
    box.appendChild(el("div", { class: "hint" }, parts.join(" · ") + (f.version ? " · " + f.version : "")));
    if (f.avail_known && !f.fits) {
      const warn = el("div", { class: "upd-target-warn" },
        el("strong", {}, t("It will not fit.")),
        el("span", {}, t("Free at least {0} MiB more in {1}, or point the “sing-box binary” setting at a directory with room — the panel installs engines beside it.", String(f.shortfall_mib || 1), f.dir || "?")));
      box.appendChild(warn);
      // Name the disk that would take it, if one is mounted. Asked only in the refusal path: the
      // storage read is cheap, but a suggestion is only worth making where it changes the answer.
      api.get("/api/updater/storage").then(s => {
        const fits = (s.roomier || []).filter(r => r.free_bytes >= f.need_bytes);
        if (fits.length) {
          warn.appendChild(el("span", {},
            t("{0} ({1}) has {2} free — enough for this.", fits[0].path, fits[0].filesystem || "?", fmtBytes(fits[0].free_bytes))));
        }
      }).catch(() => {});
    }
  }).catch(err => {
    // "Could not measure" must never render as "fits": an unknown is reported as an unknown.
    box.innerHTML = "";
    box.appendChild(el("div", { class: "hint" }, t("Size not measured: {0}", err.message)));
  });
  return box;
}

// awgStatusBlock is what the AmneziaWG 3 row is about: the router's own AmneziaWG module, how each
// AmneziaWG connection here runs - the same decision the plugin and the native planner act on, from
// the daemon - and, once installed, what the component costs on flash and in RAM.
function awgStatusBlock(a) {
  const box = el("div", { class: "upd-awg" }, el("div", { class: "hint" }, awgKernelLine(a)), awgBuiltinLine(a));
  const conns = a.connections || [];
  if (!conns.length) {
    box.appendChild(el("div", { class: "hint" }, t("No AmneziaWG connection is configured.")));
  } else {
    const list = el("ul", { class: "hint upd-awg-conns" });
    conns.forEach(c => list.appendChild(el("li", {},
      el("strong", {}, c.name), " · ", awgPathLabel(c.path), " · ", t("needs AmneziaWG {0}", c.need), " — ", c.reason)));
    box.appendChild(list);
  }
  if (a.footprint) box.appendChild(el("div", { class: "hint" }, awgFootprintLine(a.footprint)));
  const pending = awgPendingBlock(a);
  if (pending) box.appendChild(pending);
  return box;
}

// awgPendingBlock is what the router now carries and the running connections or netifd have not caught
// up with: connections still on amneziawg-go, which switch at their next start or by two Applies (the
// daemon's sentence - nothing restarts a working tunnel to move it), and a netifd still running an
// older AmneziaWG handler, with the restart offered and the next reboot named as the other way.
function awgPendingBlock(a) {
  if (!a || (!a.switching && !a.netifd_restart)) return null;
  const box = el("div", { class: "pm-deleg" });
  if (a.switching) box.appendChild(el("div", { class: "hint" }, a.switching));
  if (a.netifd_restart) {
    const why = t("AmneziaWG 3.x settings reach netifd's new handler only after the network service restarts: now (every link drops for a few seconds) or at the next reboot.");
    box.appendChild(el("div", { class: "hint upd-usage" }, why));
    box.appendChild(el("div", { class: "acts" }, el("button", { class: "btn btn-sm", type: "button",
      onclick: async ev => {
        const btn = ev.currentTarget;
        if (!await modalConfirm(t("Restart the network service now") + "? " + why)) return;
        btn.disabled = true;
        try {
          const r = await api.post("/api/updater/awg/restart-network", {});
          toast(r.summary, "ok");
          // The links come back within seconds; the row is read again once netifd has restarted.
          setTimeout(route, r.restarting ? 8000 : 0);
        } catch (err) {
          toast(err.message, "err");
          btn.disabled = false;
        }
      } }, t("Restart the network service now"))));
  }
  return box;
}

function awgKernelLine(a) {
  if (a.firmware_owned) {
    return t("The firmware runs its own tunnels on this router's AmneziaWG module, so a connection it cannot carry runs on amneziawg-go.");
  }
  if (a.kernel === "unknown") return t("The AmneziaWG kernel module could not be checked: {0}", a.probe_error || "");
  if (a.kernel === "none") {
    return a.tun ? t("No AmneziaWG kernel module here; amneziawg-go runs on /dev/net/tun.")
      : t("No AmneziaWG kernel module and no /dev/net/tun: AmneziaWG cannot run on this router.");
  }
  return t("Kernel module: AmneziaWG {0}.", a.kernel);
}

// awgBuiltinLine sets the router's own AmneziaWG against amneziawg-go's, and when the component is
// optional here says so and what it is for - the row must not read as a gap on a working router.
function awgBuiltinLine(a) {
  const own = a.builtin && !["none", "unknown"].includes(a.builtin);
  const parts = [];
  if (own && a.newest && a.builtin !== a.newest) {
    parts.push(t("This router's own AmneziaWG carries settings up to generation {0}; amneziawg-go runs generation {1}.",
      a.builtin, a.newest));
  }
  if (a.optional) {
    parts.push(t("Optional: no connection needs it yet. Install it to run connections with AmneziaWG 3.x settings, or to run any connection on it: choose amneziawg-go as the engine in the connection's editor. Under load it holds 60-120 MB of RAM."));
  }
  return parts.length ? el("div", { class: "hint upd-awg-builtin" }, parts.join(" ")) : null;
}

function awgPathLabel(path) {
  return ({
    native: t("the router's own AmneziaWG"), kernel: t("kernel module"),
    userspace: t("amneziawg-go (userspace)"), unavailable: t("cannot run"),
  })[path] || path;
}

function awgFootprintLine(f) {
  const mb = n => (n / 1048576).toFixed(1) + " MB";
  let line = f.form === "compressed"
    ? t("Kept compressed: {0} on flash; it is unpacked into RAM when it starts ({1}).", mb(f.flash_bytes),
      f.ram_bytes ? mb(f.ram_bytes) : t("not unpacked yet"))
    : t("{0} on flash.", mb(f.flash_bytes));
  if (f.running) {
    line += " " + tn("{0} process running|{0} processes running", f.running);
    if (f.rss_bytes) line += " · " + t("{0} resident", mb(f.rss_bytes));
  }
  return line;
}

// awgFeedBox offers AmneziaWG 3.1 from WayHop's own feed, through the installer the daemon embeds
// (GET /api/updater/awg/fit is its dry run). The plan comes first and says which path the installer
// would take here and why - the kernel module for this release and target, userspace amneziawg-go
// with its memory profile, or a refusal with the reason - and Install then runs exactly that path.
// When a connection needs it and nothing is installed the plan is asked at once; otherwise on first
// open, because the dry run reads the package database and the feed, which a router that is not
// waiting on it should not pay for on every visit. With amneziawg-go already there the feed is a
// choice (the kernel path, a packaged build), not a gap.
function awgFeedBox(e) {
  const box = el("div", { class: "pm-deleg" });
  const out = el("div", { class: "pm-cmd" });
  const status = el("div", { class: "hint" });
  box.appendChild(out);
  box.appendChild(status);
  const plan = async () => {
    out.innerHTML = "";
    status.textContent = t("Checking what would run…");
    let ans;
    try { ans = await api.get("/api/updater/awg/fit"); } catch (err) { status.textContent = err.message; return; }
    status.textContent = "";
    out.appendChild(el("div", { class: ans.installable ? "hint" : "hint upd-err" },
      (ans.installable ? t("This will install:") : t("Not possible here:")) + " " + ans.summary));
    awgFeedLog(out, ans.run);
    // The install changes netifd's AmneziaWG handler: restarting the network service with it is the
    // operator's call (it drops every link), so it is offered and left off.
    const restart = ans.installable && ans.netifd_restart ? el("input", { type: "checkbox" }) : null;
    if (restart) {
      out.appendChild(el("label", { class: "check" }, restart,
        t("Restart the network service after installing (every link drops for a few seconds)")));
    }
    const acts = el("div", { class: "acts" });
    if (ans.installable) {
      acts.appendChild(el("button", { class: e.awg.needed ? "btn btn-sm btn-primary" : "btn btn-sm",
        "aria-label": t("Install {0}", "AmneziaWG " + (ans.run.generation || e.awg.newest || "")),
        onclick: ev => awgFeedInstall(ans, ev.currentTarget, out, status, restart) }, t("Install")));
    }
    // The way round, named as such: the release asset has its own flash, compressed-store and memory
    // pre-flights, so offering it after a refusal is an offer the daemon will still check.
    if (ans.fallback && !(e.installed || {}).present) {
      acts.appendChild(el("button", { class: "btn btn-sm", onclick: ev => installLatest(e, ev.currentTarget) },
        t("Install amneziawg-go from a WayHop release instead")));
    }
    if (acts.childNodes.length) out.appendChild(acts);
  };
  if (e.awg.needed && !(e.installed || {}).present) {
    plan();
    return box;
  }
  // The same disclosure collapsedOffer gives the optional core, under the same words.
  const det = el("details", { class: "upd-offer" }, el("summary", {}, t("What installing it would add")));
  let asked = false;
  det.addEventListener("toggle", () => {
    if (asked || !det.open) return;
    asked = true;
    det.appendChild(box);
    plan();
  });
  return det;
}

// awgFeedInstall runs the approved path. The outcome is the daemon's own sentence, in a toast,
// because route() rebuilds the page: after a kernel-module install the row itself goes, replaced by
// the note that the kernel carries AmneziaWG 3.1. It does not take installedNextStep's note, whose
// "nothing is waiting on it" is about the core's dependents and would be false for a connection that
// needs amneziawg-go; the demo's sentence already says that nothing was installed. A failure stays
// on the row with the installer's log, which is what to act on.
async function awgFeedInstall(ans, btn, out, status, restart) {
  if (!await modalConfirm(t("Install from WayHop's feed: {0}?", ans.summary))) return;
  const restartNetwork = !!(restart && restart.checked);
  btn.disabled = true;
  status.textContent = t("Running…");
  try {
    const r = await api.post("/api/updater/awg/install", { mode: ans.run.path, restart_network: restartNetwork });
    toast(r.summary, "ok");
    route();
  } catch (err) {
    // The restart the operator asked for can drop this very connection before the answer arrives; the
    // page is read again (and the reconnect banner covers the seconds the router is away).
    if (restartNetwork && isNetworkError(err)) {
      status.textContent = "";
      setTimeout(route, 8000);
      return;
    }
    status.textContent = "";
    out.innerHTML = "";
    out.appendChild(el("div", { class: "hint upd-err" }, t("Install failed:") + " " + err.message));
    awgFeedLog(out, err.data && err.data.answer && err.data.answer.run);
    toast(t("{0} install failed: {1}", "AmneziaWG", err.message), "err");
    btn.disabled = false;
  }
}

// awgFeedLog is the installer's own account of a run, closed by default: the summary above is the
// answer, and the log is the evidence for when the answer is a failure.
function awgFeedLog(box, run) {
  if (!run || !(run.log || []).length) return;
  box.appendChild(el("details", { class: "pm-why" }, el("summary", { class: "hint" }, t("Installer log")),
    el("pre", { class: "pm-argv pm-effect" }, run.log.join("\n"))));
}

// awgFeedRemoval is the way back from a kernel-module install, kept behind a closed disclosure under
// the note that the kernel carries AmneziaWG: nothing is missing there, so removal must be asked for.
// It names the packages and the connections that run on them before anything is removed.
function awgFeedRemoval(e) {
  const pkgs = (e.awg.packages || []).map(k => k.name + " " + k.version).join(", ");
  const onKernel = (e.awg.connections || []).filter(c => c.path === "kernel" || c.path === "native").map(c => c.name);
  const det = el("details", { class: "upd-offer" }, el("summary", {}, t("Remove the AmneziaWG packages")));
  det.appendChild(el("div", { class: "hint" }, pkgs));
  if (onKernel.length) det.appendChild(el("div", { class: "hint upd-usage" }, t("Removing it stops: {0}.", onKernel.join(", "))));
  det.appendChild(el("button", { class: "btn btn-sm btn-danger", "aria-label": t("Remove the AmneziaWG packages"),
    onclick: async ev => {
      const btn = ev.currentTarget;
      const ask = t("Remove the AmneziaWG packages") + ": " + pkgs + "?" +
        (onKernel.length ? " " + t("Removing it stops: {0}.", onKernel.join(", ")) : "");
      if (!await modalConfirm(ask)) return;
      btn.disabled = true;
      try {
        const r = await api.del("/api/updater/awg");
        toast((r.answer && r.answer.summary) || t("Done."), "ok");
        route();
      } catch (err) {
        toast(t("Remove failed:") + " " + err.message, "err");
        btn.disabled = false;
      }
    } }, t("Remove")));
  return det;
}

// installLatest is the one-click install the AmneziaWG 3 row offers when a connection needs it: the
// newest stable version from the release listing, through the same install path as the picker.
async function installLatest(e, btn) {
  btn.disabled = true;
  try {
    const v = await api.get("/api/updater/" + encodeURIComponent(e.id) + "/versions");
    if (!v.latest) throw new Error(t("No release carries it yet."));
    await installVersion(e, v.latest, btn);
  } catch (err) {
    btn.disabled = false;
    updRowErr(updItem(e.id).vbox, err.message);
  }
}

function engineRow(e, pmKind, advanced) {
  const p = updItem(e.id);
  const installed = e.installed || {};
  const pkg = e.package_status || {};
  // "Owned by the package manager" and "we could not ask the package manager" are different answers,
  // and the panel must act the same on both: install and remove REFUSE when ownership is unverifiable
  // (engineManagedErr is fail-closed), so offering the buttons would only produce a refusal. This used
  // to collapse to a plain false and the Keenetic's Updater page grew and lost its Check and Remove
  // buttons between identical loads, depending on whether opkg answered that second.
  const unknownOwner = !!e.ownership_unknown;
  const managed = !!e.native_managed;
  const noMutate = managed || unknownOwner;
  p.name.appendChild(el("span", { class: "upd-n" }, e.name));
  p.name.appendChild(el("span", { class: "upd-r" },
    e.id === "sing-box" ? t("optional compatibility engine")
      : e.role ? t(ENGINE_ROLE_HINT[e.role] || e.role) : e.repo));
  p.inst.textContent = installed.present ? (installed.version || t("installed")) : "—";

  // `failed` is NOT a row state — the states answer "how does the installed build compare with the
  // latest one", and an engine whose install was refused is simply not installed. That is exactly why
  // the verdict could lead with "Everything is current" over a router that had just refused an
  // install: the failure was in the row and in no count. It is carried alongside the state instead.
  // An engine whose protocol the ROUTER carries in its kernel is not a missing component. Measured on
  // a live AX3000T: kmod-amneziawg, amneziawg-tools and luci-proto-amneziawg installed, the
  // module loaded, and it was carrying their tunnel — while this row said "AmneziaWG (userspace) —
  // not installed" and offered fifteen GitHub versions the install path then refused. Every word
  // true, and it reads as a gap. The daemon knew both halves and nothing put them side by side.
  const byKernel = !!e.carried_by_kernel && !installed.present;
  const managedState = ({ behind: "behind", current: "current", ahead: "ahead",
    catalog_error: "error", channel_missing: "channel_missing" })[pkg.state] || "undecidable";
  const rec = { id: e.id, failed: e.last_error || "", managed, optional: e.id === "sing-box" || !!(e.awg && !e.awg.needed),
    state: managed ? managedState : unknownOwner ? "undecidable" : installed.present ? "unchecked"
      : byKernel ? "kernel" : "absent" };
  if (managed) p.latest.textContent = pkg.latest_version || "—";
  p.state.innerHTML = "";
  p.state.appendChild(updStatePill(rec.state, rec.state === "behind"
    ? t("update → {0}", pkg.latest_version || "?") : unknownOwner ? t("owner unverified") : ""));
  if (managed) p.state.appendChild(updStatePill("managed", t("managed by {0}", pmKind || "the system")));
  if (byKernel) {
    p.vbox.appendChild(el("div", { class: "hint" },
      t("This router carries {0} in its kernel, so the userspace build is not needed here.", e.provides || e.id)));
    // The row said all three of these at once: "in the kernel", "the userspace build is not needed
    // here", and an active "Install with apk". Nothing is missing, so an install control in the
    // default view is an instruction to fix a router that is already working.
    //
    // The capability is kept, because there IS a case for it — a kernel module too old for a peer's
    // parameters, where the userspace build is the way round — but it has to be asked for. A closed
    // <details> is not an offer: it takes a deliberate open, and the reason is inside it rather than
    // implied by a button sitting next to "not needed here".
    if (pmKind && !unknownOwner && !managed) {
      const adv = el("details", { class: "upd-kernel-adv" });
      adv.appendChild(el("summary", {}, t("Install the userspace build anyway")));
      adv.appendChild(el("div", { class: "hint" },
        t("Only useful if the kernel module cannot carry a particular peer — an older module against newer parameters, for instance. It will not replace the kernel path, and both can be present at once.")));
      adv.appendChild(pmDelegation(e, pmKind, "install"));
      p.vbox.appendChild(adv);
    }
  }

  if (e.awg) {
    p.vbox.appendChild(awgStatusBlock(e.awg));
    // Where each piece came from, in the package manager's words: the kernel path's packages, and an
    // amneziawg-go the panel installed from a release asset (a package-owned one is named by the
    // managed note below). Version strings, not the binary's own claim: amneziawg-go prints a stale one.
    for (const k of e.awg.packages || []) {
      p.vbox.appendChild(el("div", { class: "hint" }, t("Installed as {0} package {1}{2}.", pmKind || "system", k.name, " · " + k.version)));
    }
    if (installed.source === "release") {
      p.vbox.appendChild(el("div", { class: "hint" }, t("Installed from a WayHop release ({0}).", installed.version || "?")));
    }
    // WayHop's own installer, where it applies here. Offered beside a package-owned amneziawg-go too:
    // the kernel module is a separate install, and the package manager owns only the binary.
    if (!unknownOwner && (e.awg.feed_modes || []).length && (e.awg.needed || e.awg.optional)) {
      p.vbox.appendChild(awgFeedBox(e));
    }
  }

  // What depends on this engine decides both questions the row exists for: whether "not installed"
  // is normal here, and whether removing it would break something. The daemon answers from the saved
  // profile (see coreDependents), so it names the operator's OWN connections rather than a category.
  const usedBy = e.used_by || [];
  if (e.role === "core") p.vbox.appendChild(usageNote(usedBy, installed.present));
  // Shown once, on the row whose install just succeeded — see updJustInstalled.
  if (updJustInstalled === e.id) {
    const converged = updJustConverged;
    const demo = updJustDemo;
    updJustInstalled = null;
    updJustConverged = false;
    updJustDemo = false;
    p.vbox.appendChild(installedNextStep(usedBy, converged, demo));
  }

  if (e.id === "sing-box" && !installed.present) {
    // The offer is only worth making when something would use it. A router that needs nothing gets
    // the "what it would unlock" list on demand instead of as a standing suggestion — the section is
    // not supposed to talk a working router into installing a core it has no use for.
    if (usedBy.length) {
      p.vbox.appendChild(unlockNote());
      p.vbox.appendChild(installCostNote(e));
    } else {
      p.vbox.appendChild(collapsedOffer(e));
    }
  }

  if (unknownOwner && !managed) {
    p.vbox.appendChild(el("div", { class: "hint" }, t("Could not check whether {0} owns this binary, so the panel will not install or remove it — that is the same answer the install path gives. Retry in a moment.", pmKind || "the package manager")));
  }
  if (managed) {
    p.vbox.appendChild(el("div", { class: "hint upd-pkg-note" },
      t("Installed as {0} package {1}{2}.", pmKind || "system", pkg.package || e.native_owner || e.id,
        pkg.installed_version ? " · " + pkg.installed_version : "")));
    if (pkg.state === "catalog_error") {
      p.vbox.appendChild(el("div", { class: "upd-remedy" },
        el("strong", {}, t("Package lists are unavailable.")),
        el("span", {}, t("Use “Refresh package lists” above, then check again."))));
    } else if (pkg.state === "channel_missing") {
      p.vbox.appendChild(el("div", { class: "upd-remedy" },
        el("strong", {}, t("No configured repository offers this package.")),
        el("span", {}, t("The installed binary is kept untouched because the package manager has no replacement for it."))));
    } else if (pkg.state === "ahead") {
      p.vbox.appendChild(el("div", { class: "hint" },
        t("The installed package is newer than anything the catalog offers, so there is nothing to update to.")));
    } else if (pkg.state === "current") {
      // The last state that said nothing. On a live AX3000T the row read "1.12.17 / 1.12.17-r1
      // / current / managed by apk / Installed as apk package sing-box · 1.12.17-r1." and stopped —
      // no Update (there is nothing to update to, which is right), but also no Remove, no Roll back
      // and no word about why. The policy is deliberate: the panel does not operate over a package
      // manager that owns the binary. Saying so is what was missing.
      p.vbox.appendChild(el("div", { class: "hint" },
        t("It matches the package catalog, so there is nothing to update. Removing it or going back to an older build runs through {0} below.", pmKind || "the package manager")));
    } else if (pkg.error) {
      // Every other state above explains itself; "unknown" fell through to silence. The row then read
      // "Installed as apk package sing-box." with no Update, no Remove, no Roll back and no reason —
      // the panel had withheld every action and said nothing about it. The daemon knows exactly why
      // (an unreadable installed version, or a package whose file list does not include the binary in
      // use, which is the guard that stops a remove taking out the wrong package), and that sentence
      // is already sanitised for display.
      p.vbox.appendChild(el("div", { class: "upd-remedy" },
        el("strong", {}, t("No package actions are offered for this one.")),
        el("span", {}, pkg.error)));
    }
    // One delegation box for every owned row, not only for the row with an update waiting. Remove
    // and Roll back are about the build that is INSTALLED; hanging them off "is there something
    // newer in the feed" is why a router whose package matched the catalog — the ordinary state —
    // offered no way to remove it at all, and why the operator went looking for a button that the
    // daemon has been able to serve since the day the plan was written.
    //
    // The one row that gets nothing is the one just above: a package whose identity the daemon could
    // not establish. Its plans block on their own checks, and a control that can only be refused is
    // not an offer.
    if (pkg.state !== "unknown") {
      p.vbox.appendChild(pmDelegation(e, pmKind, pkg.state === "behind" ? "owned" : "managed"));
    }
  } else if (!installed.present && !byKernel && !unknownOwner && pmKind && !e.companion) {
    // Install is the ONE action that can only apply while the binary is absent — and an absent binary
    // is owned by nobody, so `managed` is false and the branch above never runs for it. That is how
    // the action the operator named ("installing an absent package is not offered at all") stayed
    // unreachable while its planner branch, its allow-list entry and its apply path were all complete
    // and tested. The demo shows it plainly: it reports apk with every engine absent, and
    // /pm/plan?action=install answers `apk add sing-box` for a page that had no way to ask.
    //
    // Offered without pre-checking the feed, because the button IS the check: the daemon answers
    // either with the command or with the blocked plan and its preconditions, and on this box's own
    // feed only two of the seven engines exist as packages. Pre-filtering would cost every engine a
    // round trip on every render to hide a button whose refusal is the more useful answer.
    p.vbox.appendChild(pmDelegation(e, pmKind, "install"));
  }
  // The source-only sentence has a second render site inside rec.check's version picker, and on the
  // router both fired: "No prebuilt releases; build from source on-device (the PPA is blocked in
  // RU)." was printed twice under the AmneziaWG row. This is the owner — it renders without waiting
  // for a check — and the picker defers to it (see rec.check below).
  if (e.source_only) p.vbox.appendChild(el("div", { class: "hint upd-src-note" }, e.note || "No prebuilt releases."));
  updRowErr(p.vbox, e.last_error ? t("Last update failed:") + " " + e.last_error : "");

  rec.check = async () => {
    // Package-owned rows were already checked against apk/opkg while the engine list was built.
    // GitHub tags are not an update source for a package-owned file and must not overwrite this
    // truthful state with an unrelated network result.
    if (managed) return;
    p.state.innerHTML = "";
    p.state.appendChild(el("span", { class: "pill muted" }, t("checking…")));
    try {
      const v = await api.get("/api/updater/" + encodeURIComponent(e.id) + "/versions");
      const st = engineStateFrom(v);
      // engineStateFrom compares versions and knows nothing about the kernel, so it reads an absent
      // userspace binary as "not installed" — and a check relabelled the row from "in the kernel" to
      // exactly the wording the row was rewritten to stop showing. The kernel does not stop carrying
      // the protocol because somebody pressed Check all.
      rec.state = byKernel ? "kernel" : st.state;
      p.inst.textContent = v.installed || "—";
      p.latest.textContent = st.latest || "—";
      p.state.innerHTML = "";
      p.state.appendChild(updStatePill(rec.state, rec.state === "kernel" ? "" : (st.note || "")));
      // A source-built engine offers a tag picker rather than a download; it lives in the row's own
      // detail area so two rows can never share one picker.
      const pickable = (v.versions && v.versions.length) ? v.versions : null;
      const old = p.vbox.querySelector(".upd-pick");
      if (old) old.remove();
      if (pickable) {
        const sel = el("select", {}, ...pickable.map(x => el("option", { value: x }, x + (x === v.latest ? "  (latest)" : ""))));
        // GitHub returns prereleases first. The server marks the newest stable build as `latest`, but
        // a plain select defaults to the first option and previously offered a beta even while the
        // same row labelled a stable version as latest.
        if (v.latest && pickable.includes(v.latest)) sel.value = v.latest;
        sel.setAttribute("aria-label", t("Version"));
        const pick = el("div", { class: "upd-pick" }, sel);
        if (byKernel) {
          // The same rule as the row's install control, one step later: after a check this listed
          // fifteen GitHub versions with an Install button beside a row that says the kernel already
          // carries the protocol. The versions stay visible — knowing what exists is not an offer to
          // install it — and the deliberate route is the disclosure above.
          pick.appendChild(el("span", { class: "hint" },
            t("Not offered here: the kernel carries {0}. Use “Install the userspace build anyway” above if you need it.", e.provides || e.id)));
        } else if (noMutate) {
          // The row's own action buttons are already withheld for these two states, but the picker
          // is built by rec.check — which "Check all" runs for every row, owned or not. So a
          // package-manager-owned engine still grew a self-managed "Install selected", offering to
          // overwrite a binary opkg or apk owns; the install path refuses it, after the click.
          pick.appendChild(el("span", { class: "hint" }, managed
            ? t("Not offered here: {0} owns this binary — use the package-manager actions above.", pmKind || "the package manager")
            : t("Not offered here: the panel could not verify who owns this binary.")));
        } else if (!v.source_only) {
          pick.appendChild(el("button", { class: "btn btn-sm", "aria-label": t("Install selected version of {0}", e.name),
            onclick: ev => installVersion(e, sel.value, ev.currentTarget) }, "Install selected"));
          // What the chosen version COSTS, before it is chosen — the same question the absent-engine
          // row answers and this one did not. Pressing Install here downloads and writes exactly as
          // much as a first install (~69 MB for sing-box), and on a small-flash router the refusal
          // arrived only after the click, which is the failure /fit was written to prevent. It
          // follows the selection because the answer is per-version.
          let cost = installCostNote(e, sel.value);
          pick.appendChild(cost);
          sel.addEventListener("change", () => {
            const fresh = installCostNote(e, sel.value);
            cost.replaceWith(fresh);
            cost = fresh;
          });
        } else {
          // The row already carries this sentence (engineRow's source_only branch, two lines above
          // the picker), and printing it again here put it on the AmneziaWG row twice. Update the
          // one that is there rather than adding a second; the picker only grows its own copy when
          // the row never rendered one, so a select with no Install button is still explained.
          const shown = p.vbox.querySelector(".upd-src-note");
          if (shown) { if (v.note) shown.textContent = v.note; }
          else pick.appendChild(el("span", { class: "hint upd-src-note" }, v.note || "Build from source on the device."));
        }
        p.vbox.appendChild(pick);
      }
    } catch (err) {
      rec.state = "error";
      p.state.innerHTML = "";
      p.state.appendChild(updStatePill("error", err.message));
    }
  };
  (advanced ? updAdvRows : updRows).set(e.id, rec);

  // el() drops null children, appendChild does NOT — it throws "parameter 1 is not of type 'Node'".
  // This line used to pass `managed ? null : <button>`, so on any router where an engine is owned by
  // the package manager the throw escaped renderUpdater mid-loop and route()'s catch turned the whole
  // page into an error: header, verdict and the WayHop row still on screen, every engine row and every
  // engine control gone. The Keenetic reports opkg and owns sing-box, so it hit this every time that
  // flag was set; the demo owns nothing through a package manager and never did.
  // Where WayHop's installer applies, its box above carries Install and offers this release-asset
  // install itself as the way round when the feed cannot serve the router.
  if (!noMutate && e.awg && (e.awg.needed || e.awg.optional) && !installed.present && !(e.awg.feed_modes || []).length) {
    // Primary only when a connection needs it: an optional component is offered, not urged.
    p.acts.appendChild(el("button", { class: e.awg.needed ? "btn btn-sm btn-primary" : "btn btn-sm", "aria-label": t("Install {0}", e.name),
      onclick: ev => installLatest(e, ev.currentTarget) }, t("Install")));
  }
  if (!noMutate) {
    p.acts.appendChild(el("button", { class: "btn btn-sm", "aria-label": "Check updates for " + e.name,
      onclick: async () => { await rec.check(true); paintUpdVerdict(); } }, "Check updates"));
  }
  if (!noMutate && installed.present && !e.source_only) {
    p.acts.appendChild(el("button", { class: "btn btn-sm btn-danger", "aria-label": "Remove " + e.name,
      onclick: ev => removeEngine(e, ev.currentTarget) }, "Remove"));
  }
  return p.item;
}

async function selfUpdate(btn) {
  if (!await modalConfirm("Download the latest WayHop release, replace the running binary, and restart the service? The panel will briefly drop, then return.")) return;
  btn.setAttribute("disabled", "true"); btn.textContent = t("Updating…");
  try {
    const r = await api.post("/api/updater/self/install", {});
    toast(t("WayHop → {0}", r.installed) + (r.restarting ? " · " + t("restarting…") : (r.note ? " · " + r.note : "")), "ok");
    // The daemon swaps its binary and restarts ~1s after responding, so the panel is about to
    // drop. Poll /api/health and reload when it returns (same recovery restartService uses) —
    // otherwise the user is stranded on a frozen Updater page with a disabled button.
    if (r.restarting) showReconnect();
    // No restart (demo mode, or the daemon's restart command failed to start): the panel is NOT
    // about to drop, so re-enable the button instead of leaving it stuck on "Updating…" forever.
    else { btn.removeAttribute("disabled"); btn.textContent = t("Update now"); }
  } catch (e) {
    // A DROPPED CONNECTION here is EXPECTED, not a failure: the daemon can swap its binary and
    // restart before the HTTP response finishes, so the POST rejects with a network error. Treat
    // that as "restarting" and raise the auto-reconnect+reload overlay (which polls /api/health and
    // reloads when the new binary is up) — this is the blank-page-until-manual-refresh fix. Only a
    // real (application) error is an actual update failure.
    if (isNetworkError(e)) { showReconnect(); return; }
    // The refusal has to survive being read. On a small-flash router this is the ROUTINE outcome,
    // not the edge case, and the daemon's answer is a paragraph the operator acts on: measured on
    // a live AX3000T, WayHop's own row would answer "not enough free space to self-update
    // safely on /usr/sbin (~13 MiB free, need ~27 MiB for the new binary + backup — free at least
    // 14 MiB more) — free space, mount external storage, or update over SSH". That sentence lived
    // only in a toast, which expires while you are still deciding what to free.
    //
    // Same treatment the engine rows already give their failures, through the same helper.
    // One sentence, composed once, in both places — and it is the key the dictionaries already
    // carry, so the row does not introduce an untranslated string of its own.
    const failed = t("Update failed: {0}", e.message);
    toast(failed, "err");
    const selfRow = btn.closest(".upd-item");
    updRowErr(selfRow && selfRow.querySelector(".upd-detail"), failed);
    btn.removeAttribute("disabled"); btn.textContent = t("Update now");
  }
}

async function selfAutoToggle(tog) {
  const on = !tog.classList.contains("on");
  try {
    await api.put("/api/updater/self/auto", { enabled: on });
    tog.classList.toggle("on", on);
    tog.setAttribute("aria-checked", on ? "true" : "false"); // flipped in place, no re-render
    toast(on ? t("Auto-update enabled") : t("Auto-update disabled"), "ok");
  } catch (e) { toast(e.message, "err"); }
}

async function installVersion(e, version, btn) {
  if (!version) return;
  if (!await modalConfirm(t("Download and install {0} {1} for this router?", e.name, version))) return;
  btn.setAttribute("disabled", "true"); btn.textContent = "Installing…";
  try {
    const r = await api.post("/api/updater/" + encodeURIComponent(e.id) + "/install", { version });
    // The same outcome the delegation reports, on the path that has been sending it since it was
    // written: the daemon says `reload_error` when the new binary did not come back, and this toast
    // used to announce the install as a plain success regardless. An install that leaves the router
    // without a datapath is not an "ok".
    if (r.reload_error) toast(t("The core did not restart:") + " " + r.reload_error, "err");
    else if (r.converge_error) toast(t("Installed, but the router could not be brought back in line: {0}", r.converge_error), "err");
    else toast(e.name + " → " + r.installed + (r.reloaded ? " (reloaded)" : r.converged ? " (running)" : ""), "ok");
    // Hand the OUTCOME to the render that follows, not just the fact that something was installed.
    updJustInstalled = e.id;
    updJustConverged = !!r.converged;
    updJustDemo = !!r.demo;
    route();
  } catch (err) {
    // The toast is the page-level half and it lives outside the page container, so it is read with
    // no row under it — on the router it landed below the "Advanced" disclosure, a paragraph about
    // free space with nothing to say which engine it was about. Name the engine in it.
    toast(t("{0} install failed: {1}", e.name, err.message), "err");
    // `.card` used to be the fallback here, and it could only ever be wrong: the rows live inside
    // one `.card upd-table`, so `card.querySelector(".vbox")` would have found the FIRST row's
    // detail area — WayHop's — and filed this engine's failure under a different component. A row
    // we cannot locate gets the toast and nothing else.
    const row = btn.closest(".upd-item");
    updRowErr(row && row.querySelector(".upd-detail"), t("Install failed:") + " " + err.message);
    // The verdict counts what the rows carry, so a failure that arrives after the render has to be
    // recorded there too — otherwise the headline keeps the answer it computed before the click.
    const rec = updRows.get(e.id) || updAdvRows.get(e.id);
    if (rec) { rec.failed = err.message; paintUpdVerdict(); }
    btn.removeAttribute("disabled"); btn.textContent = "Install selected";
  }
}

async function removeEngine(e, btn) {
  // The confirmation names what would stop working, because that is the whole question. "Delete the
  // installed sing-box binary?" is answerable only by someone who already knows which of their
  // connections run on it — and the daemon knows, so asking the operator to remember is asking them
  // to guess with the datapath.
  const usedBy = e.used_by || [];
  const ask = usedBy.length
    ? t("Delete the installed {0} binary? {1} would stop working until it is installed again.", e.name, usedBy.join(", "))
    : t("Delete the installed {0} binary from this router? Nothing in this profile uses it, so no routing changes.", e.name);
  if (!await modalConfirm(ask)) return;
  btn.setAttribute("disabled", "true"); btn.textContent = t("Removing…");
  // The core cannot be deleted out from under a router that is running on it, so the daemon refuses
  // once and says what stopping it costs. That refusal is a QUESTION — the same one the package path
  // asks — and it was reaching the operator as the literal sentence "resend with stop:true", an
  // instruction to a program printed to a person holding a mouse. Ask it, and send the answer back
  // with the SAME request: a yes here approves the stop, never a different operation.
  const run = (stop) => api.del("/api/updater/" + encodeURIComponent(e.id), stop ? { stop: true } : undefined);
  try {
    let r;
    try {
      r = await run(false);
    } catch (err) {
      if (!(err.data && err.data.needs_stop)) throw err;
      if (!await modalConfirm(err.message)) {
        btn.removeAttribute("disabled"); btn.textContent = t("Remove");
        return;
      }
      r = await run(true);
    }
    toast(r && r.stopped ? t("{0} stopped and removed", e.name) : t("{0} removed", e.name), "ok");
    route();
  } catch (err) { toast(t("Remove failed:") + " " + err.message, "err"); btn.removeAttribute("disabled"); btn.textContent = t("Remove"); }
}

