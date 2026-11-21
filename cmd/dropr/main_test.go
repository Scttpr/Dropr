package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/scttpr/dropr/internal/audit"
	"github.com/scttpr/dropr/internal/config"
	"github.com/scttpr/dropr/internal/db"
	"github.com/scttpr/dropr/internal/httpx"
	"github.com/scttpr/dropr/internal/ids"
	"github.com/scttpr/dropr/internal/seal"
	"github.com/scttpr/dropr/internal/server"
	"github.com/scttpr/dropr/internal/store"
)

func writeConfig(t *testing.T) (string, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "refresh")
	secret := filepath.Join(dir, "secret")
	_ = os.WriteFile(key, bytes.Repeat([]byte{1}, 32), 0o600)
	_ = os.WriteFile(secret, []byte("s\n"), 0o600)
	p := filepath.Join(dir, "dropr.toml")
	_ = os.WriteFile(p, []byte(`
mode = "dev"
tls = "proxy"
public_url = "http://localhost:8080"
data_dir = "`+dir+`"
refresh_key_file = "`+key+`"
[oidc]
issuer = "http://localhost:8180/realms/dropr"
client_id = "dropr"
client_auth = "client_secret"
client_secret_file = "`+secret+`"
required_role = "Dropr.User"
`), 0o600)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, cfg
}

func seed(t *testing.T, cfg *config.Config) *store.User {
	t.Helper()
	ctx := context.Background()
	d, err := db.Open(ctx, server.DBPath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	st := store.New(d)
	u, _, err := st.ProvisionUser(ctx, cfg.OIDC.Issuer, "alice-sub", "Alice\x1b[31m", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := st.CreateSession(ctx, &store.Session{IDHash: ids.Hash(ids.NewSecret()), UserID: u.ID, CreatedAt: now, LastSeenAt: now, RevalidatedAt: now}); err != nil {
		t.Fatal(err)
	}
	return u
}

func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestUserCommands(t *testing.T) {
	cfgPath, cfg := writeConfig(t)
	u := seed(t, cfg)

	code, out, _ := runCLI(t, "", "user", "list", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, u.ID) || strings.Contains(out, "\x1b") {
		t.Fatalf("list: %d %q", code, out)
	}
	code, out, errOut := runCLI(t, "", "user", "revoke", "alice-sub", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "Ended 1 session") || !strings.Contains(out, "expired their share links") {
		t.Fatalf("revoke: %d %q", code, out)
	}
	// Admin actions leave a JSON audit line on stderr (audit 2026-11b L-9).
	if !strings.Contains(errOut, `"action":"user revoke"`) || !strings.Contains(errOut, `"user":"`+u.ID+`"`) {
		t.Errorf("revoke audit line: %q", errOut)
	}
	if code, _, _ = runCLI(t, "no\n", "user", "purge", "--config", cfgPath, u.ID); code == 0 {
		t.Fatal("purge without confirmation succeeded")
	}

	mapFile := filepath.Join(t.TempDir(), "map.csv")
	_ = os.WriteFile(mapFile, []byte("old_subject,new_subject\n# comment\nalice-sub,alice-new\n"), 0o600)
	code, out, errOut = runCLI(t, "", "user", "migrate", "--config", cfgPath, "--from-issuer", cfg.OIDC.Issuer,
		"--to-issuer", "https://login.example/v2.0", "--map", mapFile, "--yes")
	if code != 0 || !strings.Contains(out, "Relinked 1") {
		t.Fatalf("migrate: %d %q %q", code, out, errOut)
	}
	for _, want := range []string{`"action":"user migrate"`, `"user":"` + u.ID + `"`, `"old_subject":"alice-sub"`,
		`"new_subject":"alice-new"`, `"new_issuer":"https://login.example/v2.0"`} {
		if !strings.Contains(errOut, want) {
			t.Errorf("migrate audit line lacks %s: %q", want, errOut)
		}
	}
	if code, _, errOut = runCLI(t, "yes\n", "user", "purge", "--config", cfgPath, "alice-new"); code != 0 {
		t.Fatal("purge failed")
	}
	if !strings.Contains(errOut, `"action":"user purge"`) || !strings.Contains(errOut, `"user":"`+u.ID+`"`) {
		t.Errorf("purge audit line: %q", errOut)
	}
	if code, _, _ = runCLI(t, "", "user", "revoke", "--config", cfgPath, "nobody"); code != 1 {
		t.Fatal("unknown user not reported")
	}
	if code, _, _ = runCLI(t, "", "user", "bogus", "--config", cfgPath); code != 2 {
		t.Fatal("unknown subcommand")
	}
}

func TestGCBackupVersion(t *testing.T) {
	cfgPath, cfg := writeConfig(t)
	seed(t, cfg)
	if code, out, _ := runCLI(t, "", "gc", "--config", cfgPath); code != 0 || !strings.Contains(out, "Removed 0") {
		t.Fatalf("gc: %q", out)
	}
	dest := filepath.Join(t.TempDir(), "b.db")
	if code, _, e := runCLI(t, "", "backup", "--config", cfgPath, "--out", dest); code != 0 {
		t.Fatal(e)
	}
	if st, err := os.Stat(dest); err != nil {
		t.Fatal(err)
	} else if st.Mode().Perm() != 0o600 {
		t.Errorf("backup mode %#o", st.Mode().Perm())
	}
	if code, _, _ := runCLI(t, "", "backup", "--config", cfgPath, "--out", dest); code != 1 {
		t.Error("backup overwrote an existing file")
	}
	// No temporary directory is left next to the destination.
	if ents, _ := os.ReadDir(filepath.Dir(dest)); len(ents) != 1 {
		t.Errorf("leftovers next to the backup: %v", ents)
	}
	if code, out, _ := runCLI(t, "", "version"); code != 0 || !strings.Contains(out, "dropr dev") {
		t.Fatal(out)
	}
	if code, _, _ := runCLI(t, ""); code != 2 {
		t.Fatal("no args")
	}
}

func TestReadMapping(t *testing.T) {
	t.Parallel()
	for name, in := range map[string]string{
		"empty":     "",
		"dup old":   "a,b\na,c\n",
		"dup new":   "a,b\nc,b\n",
		"3 fields":  "a,b,c\n",
		"empty sub": "a,\n",
	} {
		if _, err := readMapping(strings.NewReader(in)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	m, err := readMapping(strings.NewReader("a, b\n\"c,d\",e\n"))
	if err != nil || len(m) != 2 || m[0].NewSubject != "b" || m[1].OldSubject != "c,d" {
		t.Fatal(m, err)
	}
}

func FuzzReadMapping(f *testing.F) {
	f.Add("old_subject,new_subject\na,b\n")
	f.Add("\"x\"\"y\",z\n#c\n")
	f.Fuzz(func(t *testing.T, in string) {
		m, err := readMapping(strings.NewReader(in))
		if err == nil {
			for _, x := range m {
				if x.OldSubject == "" || x.NewSubject == "" {
					t.Fatal("empty subject accepted")
				}
			}
		}
	})
}

func TestHealthcheck(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	ok := httptest.NewServer(mux)
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer bad.Close()
	if code, out, e := runCLI(t, "", "healthcheck", "--url", ok.URL+"/healthz"); code != 0 || strings.TrimSpace(out) != "ok" {
		t.Fatalf("healthy: %d %s %s", code, out, e)
	}
	if code, _, _ := runCLI(t, "", "healthcheck", "--url", bad.URL+"/healthz"); code != 1 {
		t.Fatal("unhealthy server reported healthy")
	}

	// Unix-socket listener from the config.
	sock := filepath.Join(t.TempDir(), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	target, client := healthTarget(&config.Config{Listen: "unix:" + sock, TLS: config.TLSProxy})
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("unix probe: %v", err)
	}
	_ = resp.Body.Close()
	if target, _ := healthTarget(&config.Config{Listen: ":8443", TLS: config.TLSACME, Public: &url.URL{Scheme: "https", Host: "drop.example.com"}}); target != "https://127.0.0.1:8443/healthz" {
		t.Error(target)
	}
}

// TestUserDisableEnable covers `dropr user disable|enable` (audit 2026-11b
// L-3) and the share expiry they share with revoke (L-2).
func TestUserDisableEnable(t *testing.T) {
	cfgPath, cfg := writeConfig(t)
	u := seed(t, cfg)
	ctx := context.Background()
	open := func() (*db.DB, *store.Store) {
		d, err := db.Open(ctx, server.DBPath(cfg))
		if err != nil {
			t.Fatal(err)
		}
		return d, store.New(d)
	}
	d, st := open()
	now := time.Now()
	shareID, _, err := st.CreateShare(ctx, &store.NewShare{OwnerID: u.ID, Size: 16, Parts: 1, Meta: make([]byte, 20),
		ExpiresAt: now.Add(time.Hour), TokenHash: make([]byte, 32), DefaultQuota: 1 << 30}, now)
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()

	code, out, errOut := runCLI(t, "", "user", "disable", "alice-sub", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "Disabled "+u.ID) || !strings.Contains(out, "ended 1 session") {
		t.Fatalf("disable: %d %q %q", code, out, errOut)
	}
	if !strings.Contains(errOut, `"action":"user disable"`) || !strings.Contains(errOut, `"user":"`+u.ID+`"`) ||
		!strings.Contains(errOut, `"msg":"admin action"`) {
		t.Errorf("disable audit line: %q", errOut)
	}
	d, st = open()
	got, err := st.UserByID(ctx, u.ID)
	if err != nil || got.DisabledAt == nil {
		t.Fatalf("disabled_at not set: %+v %v", got, err)
	}
	var exp int64
	if err := d.R.QueryRowContext(ctx, `SELECT expires_at FROM shares WHERE id = ?`, shareID).Scan(&exp); err != nil || exp > time.Now().Unix() {
		t.Errorf("share not expired by disable: %d %v", exp, err)
	}
	_ = d.Close()
	if code, out, _ = runCLI(t, "", "user", "list", "--config", cfgPath); code != 0 || !strings.Contains(out, "DISABLED") ||
		!strings.Contains(out, got.DisabledAt.Format(time.DateOnly)) {
		t.Errorf("list does not show the disable: %q", out)
	}
	// Idempotent.
	if code, out, _ = runCLI(t, "", "user", "disable", u.ID, "--config", cfgPath); code != 0 || !strings.Contains(out, "already disabled") {
		t.Errorf("disable again: %d %q", code, out)
	}

	code, out, errOut = runCLI(t, "", "user", "enable", u.ID, "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "Enabled "+u.ID) {
		t.Fatalf("enable: %d %q", code, out)
	}
	if !strings.Contains(errOut, `"action":"user enable"`) || !strings.Contains(errOut, `"user":"`+u.ID+`"`) {
		t.Errorf("enable audit line: %q", errOut)
	}
	d, st = open()
	if got, err := st.UserByID(ctx, u.ID); err != nil || got.DisabledAt != nil {
		t.Errorf("disabled_at not cleared: %+v %v", got, err)
	}
	// Enabling does not bring the share back.
	if err := d.R.QueryRowContext(ctx, `SELECT expires_at FROM shares WHERE id = ?`, shareID).Scan(&exp); err != nil || exp > time.Now().Unix() {
		t.Errorf("share live again after enable: %d %v", exp, err)
	}
	_ = d.Close()
	if code, out, _ = runCLI(t, "", "user", "enable", u.ID, "--config", cfgPath); code != 0 || !strings.Contains(out, "not disabled") {
		t.Errorf("enable again: %d %q", code, out)
	}

	for _, sub := range []string{"disable", "enable"} {
		if code, _, errOut = runCLI(t, "", "user", sub, "nobody", "--config", cfgPath); code != 1 || !strings.Contains(errOut, `no user matches "nobody"`) {
			t.Errorf("%s of an unknown user: %d %q", sub, code, errOut)
		}
		if code, _, _ = runCLI(t, "", "user", sub, "--config", cfgPath); code != 2 {
			t.Errorf("%s without a user: %d", sub, code)
		}
	}
}

// TestFileCleanupCommands checks that gc and purge remove blob files, not
// just rows.
func TestFileCleanupCommands(t *testing.T) {
	cfgPath, cfg := writeConfig(t)
	u := seed(t, cfg)
	ctx := context.Background()
	d, err := db.Open(ctx, server.DBPath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(d)
	blobs, err := server.NewBlobStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	put := func(id string) string {
		if err := blobs.WritePart(id, 0, 16, bytes.NewReader(make([]byte, 16))); err != nil {
			t.Fatal(err)
		}
		return filepath.Join(blobs.Root(), id[0:2], id[2:4], id)
	}
	// An expired share and a live one.
	_, expired, err := st.CreateShare(ctx, &store.NewShare{OwnerID: u.ID, Size: 16, Parts: 1, Meta: make([]byte, 20),
		ExpiresAt: now.Add(-time.Minute), TokenHash: make([]byte, 32), DefaultQuota: 1 << 30}, now)
	if err != nil {
		t.Fatal(err)
	}
	_, live, _ := st.CreateShare(ctx, &store.NewShare{OwnerID: u.ID, Size: 16, Parts: 1, Meta: make([]byte, 20),
		ExpiresAt: now.Add(time.Hour), TokenHash: make([]byte, 32), DefaultQuota: 1 << 30}, now)
	expiredDir, liveDir := put(expired), put(live)
	orphanDir := put(ids.New())
	old := now.Add(-2 * time.Hour)
	_ = os.Chtimes(orphanDir, old, old)
	_ = d.Close()

	if code, out, e := runCLI(t, "", "gc", "--config", cfgPath); code != 0 || !strings.Contains(out, "2 expired or abandoned") {
		t.Fatalf("gc: %q %s", out, e)
	}
	for dir, want := range map[string]bool{expiredDir: false, orphanDir: false, liveDir: true} {
		if _, err := os.Stat(dir); (err == nil) != want {
			t.Errorf("%s exists=%v, want %v", dir, err == nil, want)
		}
	}
	if code, out, _ := runCLI(t, "", "user", "purge", "--yes", "--config", cfgPath, u.ID); code != 0 || !strings.Contains(out, "deleted 1 file") {
		t.Fatalf("purge: %q", out)
	}
	if _, err := os.Stat(liveDir); err == nil {
		t.Error("purge left blob files")
	}
}

func TestParseFlagsAndPositionals(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args    []string
		pos     []string
		cfg     string
		wantErr bool
	}{
		{[]string{"a", "--config", "c", "b"}, []string{"a", "b"}, "c", false},
		{[]string{"--config", "c", "--", "-x", "--config"}, []string{"-x", "--config"}, "c", false},
		{[]string{"a", "--", "-b"}, []string{"a", "-b"}, defaultConfig, false},
		{[]string{"--"}, nil, defaultConfig, false},
		{[]string{"-b"}, nil, "", true},
	} {
		fs, cfg := newFlags("t", io.Discard)
		pos, err := parse(fs, tc.args)
		if (err != nil) != tc.wantErr {
			t.Errorf("%q: err %v", tc.args, err)
			continue
		}
		if !tc.wantErr && (!slices.Equal(pos, tc.pos) || *cfg != tc.cfg) {
			t.Errorf("%q: got %q config %q, want %q config %q", tc.args, pos, *cfg, tc.pos, tc.cfg)
		}
	}
}

// log-ref prints the references the server logs: the same derivation from
// the refresh_key, the fragment of a link URL ignored and never echoed.
func TestLogRef(t *testing.T) {
	t.Parallel()
	p, cfg := writeConfig(t)
	refs, err := audit.RefsFor(cfg.RefreshKey)
	if err != nil {
		t.Fatal(err)
	}
	ipKey, _ := seal.Derive(cfg.RefreshKey, seal.InfoIPHash)
	hasher := httpx.NewIPHasher(ipKey)
	// An ID may start with "-" (base64url): it goes after "--".
	id := "-" + ids.New()[1:]
	key := "c2VjcmV0LWtleS1vZi10aGUtbGluaw"
	code, out, errOut := runCLI(t, "", "log-ref", "--config", p, "--", id, "https://drop.example/s/"+id+"#"+key, "/r/"+id,
		"192.0.2.7", "::ffff:192.0.2.7", "2001:db8::1")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	link := "link " + refs.Link(id)
	ip4 := "ip " + hasher.Short(netip.MustParseAddr("192.0.2.7"))
	want := strings.Join([]string{link, link, link, ip4, ip4, "ip " + hasher.Short(netip.MustParseAddr("2001:db8::1"))}, "\n") + "\n"
	if out != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out, want)
	}
	if strings.Contains(out+errOut, key) {
		t.Error("the link key was printed")
	}

	code, out, errOut = runCLI(t, "", "log-ref", "--config", p, "--", id, "https://drop.example/x/abc#"+key, "not-an-id")
	if code != 2 || out != link+"\n" || !strings.Contains(errOut, "argument 2, 3") || strings.Contains(errOut, key) || strings.Contains(errOut, "not-an-id") {
		t.Fatalf("invalid: %d %q %q", code, out, errOut)
	}
	if code, _, _ := runCLI(t, "", "log-ref", "--config", p); code != 2 {
		t.Errorf("no argument: %d", code)
	}
}
