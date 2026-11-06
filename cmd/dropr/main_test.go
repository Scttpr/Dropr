package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scttpr/dropr/internal/config"
	"github.com/scttpr/dropr/internal/db"
	"github.com/scttpr/dropr/internal/ids"
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
	code, out, _ = runCLI(t, "", "user", "revoke", "alice-sub", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "Ended 1 session") {
		t.Fatalf("revoke: %d %q", code, out)
	}
	if code, _, _ = runCLI(t, "no\n", "user", "purge", "--config", cfgPath, u.ID); code == 0 {
		t.Fatal("purge without confirmation succeeded")
	}

	mapFile := filepath.Join(t.TempDir(), "map.csv")
	_ = os.WriteFile(mapFile, []byte("old_subject,new_subject\n# comment\nalice-sub,alice-new\n"), 0o600)
	code, out, errOut := runCLI(t, "", "user", "migrate", "--config", cfgPath, "--from-issuer", cfg.OIDC.Issuer,
		"--to-issuer", "https://login.example/v2.0", "--map", mapFile, "--yes")
	if code != 0 || !strings.Contains(out, "Relinked 1") {
		t.Fatalf("migrate: %d %q %q", code, out, errOut)
	}
	if code, _, _ = runCLI(t, "yes\n", "user", "purge", "--config", cfgPath, "alice-new"); code != 0 {
		t.Fatal("purge failed")
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
	if _, err := os.Stat(dest); err != nil {
		t.Fatal(err)
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
