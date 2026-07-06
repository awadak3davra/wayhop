package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"wayhop/internal/importer"
	"wayhop/internal/initserver"
	"wayhop/internal/model"
	"wayhop/internal/netdiag"
	"wayhop/internal/serverstore"
	"wayhop/internal/updater"
	"wayhop/internal/util"
)

// sshKnownHostsPath is the persistent, WayHop-owned known_hosts file used to pin
// provisioned-server SSH host keys. It lives next to the sing-box config (a writable,
// persistent WR-owned directory) so the pin survives reboots — unlike a router's default
// known_hosts, which may be non-persistent (re-TOFU each reboot) or unreadable. Set as
// Creds.KnownHostsFile on every Provision call; SingBox.Config is fixed at startup, so
// reading s.cfg directly here is race-safe (matches New()'s direct read).
func (s *Server) sshKnownHostsPath() string {
	return filepath.Join(filepath.Dir(s.cfg.SingBox.Config), "ssh_known_hosts")
}

// ---- saved-server registry (redundancy: manage several servers) ----

// handleServers lists saved servers (GET) or upserts one (POST). Credentials are
// never part of a server record.
func (s *Server) handleServers(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, s.servers.List())
		return
	}
	var sv serverstore.Server
	if err := json.NewDecoder(r.Body).Decode(&sv); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid server JSON")
		return
	}
	if !netdiag.ValidTarget(sv.Host) {
		writeErr(w, http.StatusBadRequest, "enter a valid host or IP")
		return
	}
	if sv.User != "" && !netdiag.ValidTarget(sv.User) {
		writeErr(w, http.StatusBadRequest, "enter a valid SSH user")
		return
	}
	if sv.Port == 0 {
		sv.Port = 22
	}
	if sv.User == "" {
		sv.User = "root"
	}
	if sv.ID == "" {
		sv.ID = "srv-" + slug(sv.Host)
	}
	if sv.Name == "" {
		sv.Name = sv.Host
	}
	if sv.Installed == nil {
		sv.Installed = []string{}
	}
	if err := s.servers.Upsert(sv); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sv)
}

func (s *Server) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	if err := s.servers.Delete(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": r.PathValue("id")})
}

// handleServerOptions returns the catalog of provisionable protocols + details.
func (s *Server) handleServerOptions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, initserver.Options())
}

// handleServerJob returns a running/finished job snapshot for the smart console.
func (s *Server) handleServerJob(w http.ResponseWriter, r *http.Request) {
	j, ok := s.jobs.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}
	writeJSON(w, http.StatusOK, j.Snapshot())
}

// ---- reachability + script preview (unchanged behaviour) ----

func (s *Server) handleServerCheck(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if b.Port == 0 {
		b.Port = 22
	}
	if !netdiag.ValidTarget(b.Host) {
		writeErr(w, http.StatusBadRequest, "enter a valid host or IP")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	ping := netdiag.Ping(ctx, b.Host, 2)
	portOpen := netdiag.DialPort(b.Host, b.Port, 8*time.Second)
	writeJSON(w, http.StatusOK, map[string]any{
		"reachable": ping.Ok || portOpen,
		"ping_ok":   ping.Ok,
		"ping_ms":   ping.AvgMs,
		"port":      b.Port,
		"port_open": portOpen,
	})
}

func (s *Server) handleServerScript(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Protocols []string `json:"protocols"`
		Host      string   `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(b.Protocols) == 0 {
		writeErr(w, http.StatusBadRequest, "pick at least one protocol")
		return
	}
	for _, p := range b.Protocols {
		if !initserver.ValidOption(p) {
			writeErr(w, http.StatusBadRequest, "unknown option: "+p)
			return
		}
	}
	if b.Host != "" && !netdiag.ValidTarget(b.Host) {
		writeErr(w, http.StatusBadRequest, "enter a valid host or IP")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"script": initserver.BuildScript(b.Protocols, b.Host, s.config().Updater.Mirrors...)})
}

// ---- provisioning (job-based, with smart console) ----

type provisionReq struct {
	ServerID  string   `json:"server_id"`
	Name      string   `json:"name"`
	Host      string   `json:"host"`
	Port      int      `json:"port"`
	User      string   `json:"user"`
	Password  string   `json:"password"`
	Key       string   `json:"key"`
	Protocols []string `json:"protocols"`
}

// handleServerProvision starts a provisioning job and returns its id immediately;
// the UI polls /api/server/job/{id} for the smart console. Credentials are used
// for this request only and never stored.
func (s *Server) handleServerProvision(w http.ResponseWriter, r *http.Request) {
	var b provisionReq
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// A saved server supplies host/user; the request still carries the creds.
	if b.ServerID != "" {
		if sv, ok := s.servers.Get(b.ServerID); ok {
			b.Host, b.Port, b.User = sv.Host, sv.Port, sv.User
			if b.Name == "" {
				b.Name = sv.Name
			}
		}
	}
	// Validate the SSH user, not just the host: b.User flows verbatim into the ssh argv
	// (user@host), so a leading-hyphen user like "-oProxyCommand=…" would be reparsed by ssh
	// as an option and run a command before auth (argument injection, CWE-88 → RCE as the
	// daemon uid). ValidTarget's leading-char class excludes '-'. This matches the invariant
	// resolveHardenTarget already enforces for the other SSH handlers (harden/lockdown/etc.).
	if !netdiag.ValidTarget(b.Host) || b.User == "" || !netdiag.ValidTarget(b.User) {
		writeErr(w, http.StatusBadRequest, "a valid host and SSH user are required")
		return
	}
	if len(b.Protocols) == 0 {
		writeErr(w, http.StatusBadRequest, "pick at least one option to set up")
		return
	}
	for _, p := range b.Protocols {
		if !initserver.ValidOption(p) {
			writeErr(w, http.StatusBadRequest, "unknown option: "+p)
			return
		}
	}
	if b.Port == 0 {
		b.Port = 22
	}
	job := s.jobs.New("provision", b.ServerID)
	go s.runProvision(job, b)
	writeJSON(w, http.StatusOK, map[string]any{"job_id": job.ID()})
}

// runProvision drives the connect -> install -> create-client -> add-to-Connections
// -> test pipeline, narrating each step into the job's console.
func (s *Server) runProvision(job *initserver.Job, b provisionReq) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	defer func() {
		if rec := recover(); rec != nil {
			job.Fail("internal error", fmt.Sprintf("%v", rec))
			job.Finish(false, nil)
		}
	}()

	name := b.Name
	if name == "" {
		name = b.Host
	}
	job.Logf("Provisioning %s (%s) — %s", name, b.Host, strings.Join(protoNames(b.Protocols), ", "))

	var output string
	if s.config().Demo {
		output = s.provisionDemo(job, b)
	} else {
		var ok bool
		output, ok = s.provisionReal(ctx, job, b)
		if !ok {
			job.Finish(false, nil)
			return
		}
	}

	// Each config is attributed to its protocol by the WR_PROTO marker the script
	// prints — never paired by position (a failed protocol would shift the index).
	configs := initserver.ExtractTagged(output)
	if len(configs) == 0 {
		job.Start("Read client configs")
		job.Fail("the installer returned no client config", "Check the install step output above — a protocol may have failed to install.")
		job.Finish(false, nil)
		return
	}

	added := []string{}       // endpoint ids created (for the job result + count)
	addedProtos := []string{} // protocol ids that ACTUALLY provisioned (config parsed + imported)
	for _, tc := range configs {
		label := initserver.OptionName(tc.Proto)
		job.Start("Create client: " + label)
		ep, err := importer.Parse(tc.Config)
		if err != nil {
			job.Fail("could not parse the "+label+" client config", err.Error())
			continue
		}
		ep.Name = name + " · " + label
		if err := s.store.UpsertEndpoint(*ep); err != nil {
			job.Fail("could not add "+label+" to Connections", err.Error())
			continue
		}
		job.OK("added “" + ep.Name + "” to Connections (" + ep.Server + ":" + itoa(ep.Port) + ")")
		added = append(added, ep.ID)
		addedProtos = append(addedProtos, tc.Proto)

		job.Start("Test " + label)
		if s.config().Demo {
			time.Sleep(350 * time.Millisecond)
			job.OK("reachable — 42 ms (simulated)")
		} else {
			testEndpointReachability(ctx, job, *ep)
		}
	}

	// Record/refresh the saved server for redundancy + future re-use. Mark only
	// the protocols that ACTUALLY provisioned (not every requested one), so the
	// servers list never claims a protocol whose install failed.
	s.saveProvisionedServer(job, b, addedProtos)

	job.Finish(len(added) > 0, map[string]any{
		"server_id":       serverIDFor(b),
		"added_endpoints": added,
		"protocols":       b.Protocols,
	})
}

func (s *Server) provisionReal(ctx context.Context, job *initserver.Job, b provisionReq) (string, bool) {
	job.Start("Connect to " + b.Host)
	if !netdiag.DialPort(b.Host, b.Port, 8*time.Second) {
		job.Fail("SSH port "+itoa(b.Port)+" is not reachable",
			"Confirm the server is up, the port is right, and no firewall blocks it. Use Check reachability first.")
		return "", false
	}
	job.OK("SSH port " + itoa(b.Port) + " open")

	job.Start("Install " + strings.Join(protoNames(b.Protocols), " + "))
	script := initserver.BuildScript(b.Protocols, b.Host, s.config().Updater.Mirrors...)
	creds := initserver.Creds{Host: b.Host, Port: b.Port, User: b.User, Password: b.Password, Key: b.Key, KnownHostsFile: s.sshKnownHostsPath()}
	out, ran, err := initserver.Provision(ctx, creds, script)
	if !ran {
		job.Fail("auto-provision unavailable on this router",
			"The router needs the ssh client (and sshpass for password auth). Install them, or use Preview script and run it on the server yourself.")
		job.Logf("one-liner: %s", initserver.OneLiner(creds))
		return "", false
	}
	if tl := tail(redactSecrets(out), 1200); tl != "" {
		job.Output(tl)
	}
	if err != nil {
		job.Fail("the installer reported an error", "Review the output above. Common causes: a blocked apt mirror/PPA, no outbound internet, or insufficient privileges (need root).")
		return out, true // keep going only if configs were still printed
	}
	job.OK("installer finished")
	return out, true
}

// provisionDemo simulates the whole pipeline (no SSH) so the flow + console can be
// exercised without a real server. It returns synthetic installer output.
func (s *Server) provisionDemo(job *initserver.Job, b provisionReq) string {
	host := b.Host
	job.Start("Connect to " + host)
	time.Sleep(300 * time.Millisecond)
	job.OK("SSH port " + itoa(b.Port) + " open (simulated)")

	job.Start("Install " + strings.Join(protoNames(b.Protocols), " + "))
	job.Logf("(demo) skipping real SSH — synthesizing a successful install")
	time.Sleep(500 * time.Millisecond)
	job.OK("installer finished (simulated)")

	var sb strings.Builder
	for _, p := range b.Protocols {
		switch p {
		case initserver.ProtoReality:
			sb.WriteString("WR_PROTO=vless-reality\n")
			sb.WriteString("WR_CLIENT_CONFIG=vless://11111111-2222-3333-4444-555555555555@" + host +
				":443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=DemoPublicKey0000000000000000000000000000000&sid=abcd1234&flow=xtls-rprx-vision&type=tcp#wayhop-server\n")
		case initserver.ProtoAmneziaWG:
			conf := "[Interface]\nPrivateKey = DEMOclientPrivateKey00000000000000000000000=\nAddress = 10.13.13.2/32\nDNS = 1.1.1.1\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 0\nS2 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n[Peer]\nPublicKey = DEMOserverPublicKey00000000000000000000000=\nEndpoint = " + host + ":51820\nAllowedIPs = 0.0.0.0/0"
			sb.WriteString("WR_PROTO=amneziawg\n")
			sb.WriteString("WR_CLIENT_CONFIG_B64=" + b64(conf) + "\n")
		}
	}
	return sb.String()
}

func (s *Server) saveProvisionedServer(job *initserver.Job, b provisionReq, installedProtos []string) {
	id := serverIDFor(b)
	existing, ok := s.servers.Get(id)
	merged := mergeStrings(existing.Installed, installedProtos)
	sv := serverstore.Server{
		ID: id, Name: util.FirstNonEmpty(b.Name, existing.Name, b.Host),
		Host: b.Host, Port: b.Port, User: b.User,
		Installed: merged, Hardened: existing.Hardened, Note: existing.Note,
		CreatedAt: util.FirstNonEmpty(existing.CreatedAt, time.Now().UTC().Format(time.RFC3339)), LastJob: job.ID(),
	}
	if !ok {
		job.Logf("saved “%s” to your servers list", sv.Name)
	}
	_ = s.servers.Upsert(sv)
}

// ---- hardening (key install, then gated password lockdown) ----

type hardenReq struct {
	ServerID string `json:"server_id"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Key      string `json:"key"`
}

func (s *Server) resolveHardenTarget(b *hardenReq) bool {
	if b.ServerID != "" {
		if sv, ok := s.servers.Get(b.ServerID); ok {
			b.Host, b.Port, b.User = sv.Host, sv.Port, sv.User
		}
	}
	if b.Port == 0 {
		b.Port = 22
	}
	return netdiag.ValidTarget(b.Host) && b.User != "" && netdiag.ValidTarget(b.User)
}

// handleServerHardenKeys generates a fresh SSH key on the server, installs the
// public key, and returns the private key in the job result for download.
func (s *Server) handleServerHardenKeys(w http.ResponseWriter, r *http.Request) {
	var b hardenReq
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !s.resolveHardenTarget(&b) {
		writeErr(w, http.StatusBadRequest, "host and SSH user are required")
		return
	}
	job := s.jobs.New("harden-keys", b.ServerID)
	go s.runHardenKeys(job, b)
	writeJSON(w, http.StatusOK, map[string]any{"job_id": job.ID()})
}

func (s *Server) runHardenKeys(job *initserver.Job, b hardenReq) {
	defer func() {
		if rec := recover(); rec != nil {
			job.Fail("internal error", fmt.Sprintf("%v", rec))
			job.Finish(false, nil)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	job.Start("Generate + install SSH key for " + b.User + "@" + b.Host)
	if s.config().Demo {
		time.Sleep(400 * time.Millisecond)
		priv := "-----BEGIN OPENSSH PRIVATE KEY-----\n(demo key — not usable)\n-----END OPENSSH PRIVATE KEY-----\n"
		job.OK("key installed into authorized_keys (simulated)")
		job.Finish(true, map[string]any{"private_key": priv, "public_key": "ssh-ed25519 AAAA...demo wayhop-managed", "filename": keyFilename(b)})
		return
	}
	creds := initserver.Creds{Host: b.Host, Port: b.Port, User: b.User, Password: b.Password, Key: b.Key, KnownHostsFile: s.sshKnownHostsPath()}
	out, ran, err := initserver.Provision(ctx, creds, initserver.HardenKeysScript(b.User))
	if !ran {
		job.Fail("auto-hardening needs the ssh client on the router", "Install ssh (and sshpass for password auth), or harden the server manually.")
		job.Finish(false, nil)
		return
	}
	priv, pub := initserver.ExtractSSHKey(out)
	if err != nil || priv == "" {
		job.Output(tail(redactSecrets(out), 800))
		job.Fail("key generation failed", "Ensure ssh-keygen exists on the server and the user's home is writable.")
		job.Finish(false, nil)
		return
	}
	job.OK("key installed into authorized_keys")
	job.Logf("DOWNLOAD AND SAVE this key before disabling password login — it is your only way back in.")
	_ = s.servers.Patch(b.ServerID, func(sv *serverstore.Server) { sv.LastJob = job.ID() })
	job.Finish(true, map[string]any{"private_key": priv, "public_key": pub, "filename": keyFilename(b)})
}

// handleServerLockdown disables SSH password auth (destructive — gated behind the
// UI confirming the key was saved and key-auth works).
func (s *Server) handleServerLockdown(w http.ResponseWriter, r *http.Request) {
	var b hardenReq
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !s.resolveHardenTarget(&b) {
		writeErr(w, http.StatusBadRequest, "host and SSH user are required")
		return
	}
	if b.Key == "" && !s.config().Demo {
		writeErr(w, http.StatusBadRequest, "lockdown requires the new SSH key (so wayhop can verify key-auth works first)")
		return
	}
	job := s.jobs.New("lockdown", b.ServerID)
	go s.runLockdown(job, b)
	writeJSON(w, http.StatusOK, map[string]any{"job_id": job.ID()})
}

func (s *Server) runLockdown(job *initserver.Job, b hardenReq) {
	defer func() {
		if rec := recover(); rec != nil {
			job.Fail("internal error", fmt.Sprintf("%v", rec))
			job.Finish(false, nil)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if s.config().Demo {
		job.Start("Verify key-based login")
		time.Sleep(300 * time.Millisecond)
		job.OK("key-auth works (simulated)")
		job.Start("Disable password authentication")
		time.Sleep(400 * time.Millisecond)
		job.OK("password auth disabled, pubkey enforced (simulated)")
		_ = s.servers.Patch(b.ServerID, func(sv *serverstore.Server) { sv.Hardened = true; sv.LastJob = job.ID() })
		job.Finish(true, map[string]any{"hardened": true})
		return
	}
	creds := initserver.Creds{Host: b.Host, Port: b.Port, User: b.User, Key: b.Key, KnownHostsFile: s.sshKnownHostsPath()}

	job.Start("Verify key-based login")
	if _, ran, err := initserver.Provision(ctx, creds, "echo WR_KEY_OK"); !ran || err != nil {
		job.Fail("could not log in with the new key", "Aborting — password login is left ENABLED so you are not locked out. Re-run key install and download the key.")
		job.Finish(false, nil)
		return
	}
	job.OK("key-based login confirmed")

	job.Start("Disable password authentication")
	out, ran, err := initserver.Provision(ctx, creds, initserver.HardenLockdownScript)
	if !ran || err != nil || !initserver.LockdownConfirmed(out) {
		job.Output(tail(redactSecrets(out), 800))
		job.Fail("could not disable password auth", "sshd may have rejected the change; password login is unchanged. Review the output and harden manually if needed.")
		job.Finish(false, nil)
		return
	}
	job.OK("password auth disabled, pubkey enforced")
	_ = s.servers.Patch(b.ServerID, func(sv *serverstore.Server) { sv.Hardened = true; sv.LastJob = job.ID() })
	job.Finish(true, map[string]any{"hardened": true})
}

// ---- per-server binary versions (check + update) ----

// serverBinUpdateReq is a hardenReq (creds + server_id) plus the binary to update.
type serverBinUpdateReq struct {
	hardenReq
	Binary  string `json:"binary"`  // singbox | awg
	Version string `json:"version"` // target x.y.z (required for github-managed)
	Confirm bool   `json:"confirm"` // explicit gate (update is destructive)
}

// handleServerCheckVersions probes a provisioned server's binary versions over SSH
// (read-only) and compares the GitHub-managed ones to the latest release.
func (s *Server) handleServerCheckVersions(w http.ResponseWriter, r *http.Request) {
	var b hardenReq
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !s.resolveHardenTarget(&b) {
		writeErr(w, http.StatusBadRequest, "host and SSH user are required")
		return
	}
	job := s.jobs.New("check-versions", b.ServerID)
	go s.runCheckVersions(job, b)
	writeJSON(w, http.StatusOK, map[string]any{"job_id": job.ID()})
}

func (s *Server) runCheckVersions(job *initserver.Job, b hardenReq) {
	defer func() {
		if rec := recover(); rec != nil {
			job.Fail("internal error", fmt.Sprintf("%v", rec))
			job.Finish(false, nil)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	job.Start("Read installed versions on " + b.Host)
	if s.config().Demo {
		time.Sleep(400 * time.Millisecond)
		job.OK("read sing-box + AmneziaWG (simulated)")
		job.Finish(true, map[string]any{"binaries": demoServerBinaries(), "arch": "x86_64", "curl": true})
		return
	}
	creds := initserver.Creds{Host: b.Host, Port: b.Port, User: b.User, Password: b.Password, Key: b.Key, KnownHostsFile: s.sshKnownHostsPath()}
	out, ran, err := initserver.Provision(ctx, creds, initserver.VersionCheckScript())
	if !ran {
		job.Fail("version check needs the ssh client on the router", "Install ssh (and sshpass for password auth), or check manually with `sing-box version`.")
		job.Finish(false, nil)
		return
	}
	if err != nil || !initserver.VerCheckRan(out) {
		job.Output(tail(redactSecrets(out), 800))
		job.Fail("couldn't read versions over SSH", "Verify the credentials and that the server is reachable.")
		job.Finish(false, nil)
		return
	}
	found := initserver.ExtractVersions(out)
	binaries := s.resolveBinaryVersions(ctx, found)
	if len(binaries) == 0 {
		job.OK("no managed binaries found on the server")
	} else {
		if found["curl"] == "0" {
			job.Output("⚠ curl not found on the server — sing-box binary updates require curl")
		}
		job.OK(versionsSummary(binaries))
	}
	_ = s.servers.Patch(b.ServerID, func(sv *serverstore.Server) { sv.LastJob = job.ID() })
	job.Finish(true, map[string]any{"binaries": binaries, "arch": found["arch"], "curl": found["curl"] == "1"})
}

// resolveBinaryVersions turns the raw probe markers into UI rows: parsed installed
// version + (for GitHub-managed binaries) the latest release + an update flag.
func (s *Server) resolveBinaryVersions(ctx context.Context, found map[string]string) []map[string]any {
	rows := make([]map[string]any, 0, len(initserver.ServerBinaries))
	for _, b := range initserver.ServerBinaries {
		raw, ok := found[b.Key]
		if !ok {
			continue // not installed on this server
		}
		installed := updater.ParseVersion(raw)
		if installed == "" {
			installed = strings.TrimSpace(raw)
		}
		row := map[string]any{"key": b.Key, "name": b.Name, "managed": b.Managed, "installed": installed}
		if b.Managed == "github" && b.Repo != "" {
			if rel, err := s.updater.Latest(ctx, updater.Engine{Repo: b.Repo}); err == nil && rel.Tag != "" {
				row["latest"] = updater.ParseVersion(rel.Tag)
				row["latest_tag"] = rel.Tag
				row["update_available"] = updater.Newer(raw, rel.Tag)
			} else {
				row["latest_error"] = "couldn't reach GitHub"
			}
		} else {
			row["note"] = "managed by apt — Update runs an apt upgrade"
		}
		rows = append(rows, row)
	}
	return rows
}

// handleServerUpdateBinary updates one binary on a provisioned server over SSH.
// DESTRUCTIVE (briefly restarts the endpoint) — gated behind an explicit confirm.
func (s *Server) handleServerUpdateBinary(w http.ResponseWriter, r *http.Request) {
	var b serverBinUpdateReq
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !s.resolveHardenTarget(&b.hardenReq) {
		writeErr(w, http.StatusBadRequest, "host and SSH user are required")
		return
	}
	if _, ok := initserver.UpdateScriptFor(b.Binary, b.Version); !ok {
		writeErr(w, http.StatusBadRequest, "unknown binary")
		return
	}
	if b.Binary == "singbox" && updater.ParseVersion(b.Version) == "" {
		writeErr(w, http.StatusBadRequest, "a target version (x.y.z) is required for sing-box")
		return
	}
	if !b.Confirm && !s.config().Demo {
		writeErr(w, http.StatusBadRequest, "update must be explicitly confirmed")
		return
	}
	job := s.jobs.New("update-binary", b.ServerID)
	go s.runUpdateServerBinary(job, b)
	writeJSON(w, http.StatusOK, map[string]any{"job_id": job.ID()})
}

func (s *Server) runUpdateServerBinary(job *initserver.Job, b serverBinUpdateReq) {
	defer func() {
		if rec := recover(); rec != nil {
			job.Fail("internal error", fmt.Sprintf("%v", rec))
			job.Finish(false, nil)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	name := b.Binary
	for _, sb := range initserver.ServerBinaries {
		if sb.Key == b.Binary {
			name = sb.Name
		}
	}
	job.Start("Update " + name + " on " + b.Host)
	if s.config().Demo {
		time.Sleep(600 * time.Millisecond)
		job.OK(name + " updated" + verSuffix(b.Version) + " (simulated)")
		job.Finish(true, map[string]any{"binary": b.Binary, "new_version": updater.ParseVersion(b.Version)})
		return
	}
	script, _ := initserver.UpdateScriptFor(b.Binary, b.Version, s.config().Updater.Mirrors...)
	creds := initserver.Creds{Host: b.Host, Port: b.Port, User: b.User, Password: b.Password, Key: b.Key, KnownHostsFile: s.sshKnownHostsPath()}
	job.Logf("the current binary is backed up as <path>.wayhop.bak on the server before the swap")
	out, ran, err := initserver.Provision(ctx, creds, script)
	if !ran {
		job.Fail("update needs the ssh client on the router", "Install ssh, or update the binary on the server manually.")
		job.Finish(false, nil)
		return
	}
	okUp, newVer := initserver.UpdateConfirmed(out)
	if err != nil || !okUp {
		job.Output(tail(redactSecrets(out), 1200))
		job.Fail("the update did not confirm success", "The service may not have restarted; a .wayhop.bak of the old binary is on the server. Review the output.")
		job.Finish(false, nil)
		return
	}
	job.OK(name + " → " + updater.ParseVersion(newVer))
	_ = s.servers.Patch(b.ServerID, func(sv *serverstore.Server) { sv.LastJob = job.ID() })
	job.Finish(true, map[string]any{"binary": b.Binary, "new_version": updater.ParseVersion(newVer)})
}

// versionsSummary is the one-line step result for a version check.
func versionsSummary(binaries []map[string]any) string {
	upd := 0
	for _, b := range binaries {
		if v, _ := b["update_available"].(bool); v {
			upd++
		}
	}
	if upd == 0 {
		return fmt.Sprintf("%d binary(ies) checked — all up to date", len(binaries))
	}
	return fmt.Sprintf("%d binary(ies) checked — %d update(s) available", len(binaries), upd)
}

func verSuffix(v string) string {
	if x := updater.ParseVersion(v); x != "" {
		return " → " + x
	}
	return ""
}

func demoServerBinaries() []map[string]any {
	return []map[string]any{
		{"key": "singbox", "name": "sing-box", "managed": "github", "installed": "1.12.8", "latest": "1.12.17", "latest_tag": "v1.12.17", "update_available": true},
		{"key": "awg", "name": "AmneziaWG", "managed": "apt", "installed": "1.0.20240306", "note": "managed by apt — Update runs an apt upgrade"},
	}
}

// ---- helpers ----

func testEndpointReachability(ctx context.Context, job *initserver.Job, ep model.Endpoint) {
	ping := netdiag.Ping(ctx, ep.Server, 2)
	port := netdiag.DialPort(ep.Server, ep.Port, 6*time.Second)
	switch {
	case port:
		job.OK("reachable — port " + itoa(ep.Port) + " open" + pingSuffix(ping))
	case ping.Ok:
		job.OK("host reachable" + pingSuffix(ping) + " (UDP port can't be probed directly)")
	default:
		job.Fail("endpoint not reachable yet", "The client was saved, but "+ep.Server+":"+itoa(ep.Port)+" did not respond. Give the server a moment, then Test it from Connections.")
	}
}

func pingSuffix(p netdiag.PingResult) string {
	if p.Ok && p.AvgMs >= 0 {
		return fmt.Sprintf(" · ping %.0f ms", p.AvgMs)
	}
	return ""
}

func protoNames(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, initserver.OptionName(id))
	}
	return out
}

func serverIDFor(b provisionReq) string {
	if b.ServerID != "" {
		return b.ServerID
	}
	return "srv-" + slug(b.Host)
}

func keyFilename(b hardenReq) string {
	return "wayhop-" + slug(b.Host) + "-ed25519"
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func mergeStrings(a, b []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range append(append([]string{}, a...), b...) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// redactSecrets blanks the marker lines that carry credential material — client
// share links/configs and the generated SSH private key — before raw installer
// output is echoed to the job console, so a secret never lands in the console log
// on a failure path. The configs are still imported and the key still handed back
// through the structured job result; only the raw-output echo is scrubbed.
func redactSecrets(out string) string {
	lines := strings.Split(out, "\n")
	for i, ln := range lines {
		for _, m := range []string{"WR_CLIENT_CONFIG=", "WR_CLIENT_CONFIG_B64=", "WR_SSH_KEY_B64="} {
			if strings.HasPrefix(strings.TrimSpace(ln), m) {
				lines[i] = m + "<redacted>"
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
