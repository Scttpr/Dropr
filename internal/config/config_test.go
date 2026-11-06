package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
)

type fixture struct {
	dir, refresh, key, keyCert, secret string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	f := fixture{
		dir:     dir,
		refresh: filepath.Join(dir, "refresh"),
		key:     filepath.Join(dir, "key.pem"),
		keyCert: filepath.Join(dir, "keycert.pem"),
		secret:  filepath.Join(dir, "secret"),
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	write(t, f.refresh, []byte(base64.StdEncoding.EncodeToString(raw)+"\n"))
	write(t, f.secret, []byte("s3cret\n"))

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	write(t, f.key, keyPEM)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dropr"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	write(t, f.keyCert, append(keyPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})...))
	return f
}

func write(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f fixture) prod(extra string) string {
	return `
public_url = "https://drop.example.com"
data_dir = "` + f.dir + `"
refresh_key_file = "` + f.refresh + `"
` + extra + `
[oidc]
issuer = "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
client_id = "abc"
client_key_file = "` + f.keyCert + `"
required_role = "Dropr.User"
required_claims = { tid = "11111111-2222-3333-4444-555555555555" }
`
}

func TestProductionDefaults(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c, err := Parse([]byte(f.prod("")))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Production() || c.TLS != TLSACME || c.Listen != ":8443" {
		t.Errorf("defaults: %+v", c)
	}
	if c.Limits.MaxFileSizeBytes != 5*GiB || c.Limits.UserQuotaBytes != 50*GiB || c.Limits.DefaultExpiryDur != 7*24*time.Hour {
		t.Errorf("limits: %+v", c.Limits)
	}
	if c.OIDC.RevalidateDur != 15*time.Minute || c.OIDC.ClientCert == nil || c.OIDC.ClientKey == nil {
		t.Errorf("oidc: %+v", c.OIDC)
	}
	if c.OIDC.RedirectURL != "https://drop.example.com/auth/callback" || c.Origin != "https://drop.example.com" {
		t.Errorf("urls: %q %q", c.OIDC.RedirectURL, c.Origin)
	}
	if len(c.RefreshKey) != 32 {
		t.Error("refresh key")
	}
	if len(c.Warnings) != 0 {
		t.Errorf("warnings: %v", c.Warnings)
	}
}

func TestDevConfig(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c, err := Parse([]byte(`
mode = "dev"
tls = "proxy"
public_url = "http://localhost:8080"
data_dir = "` + f.dir + `"
refresh_key_file = "` + f.refresh + `"
[oidc]
issuer = "http://localhost:8180/realms/dropr"
client_id = "dropr"
client_auth = "client_secret"
client_secret_file = "` + f.secret + `"
role_claim = "realm_access.roles"
required_role = "Dropr.User"
scopes = ["openid", "profile"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.OIDC.ClientSecret != "s3cret" || c.Listen != "127.0.0.1:8080" {
		t.Errorf("%+v", c.OIDC)
	}
	if strings.Join(c.OIDC.RoleClaimPath, "|") != "realm_access|roles" {
		t.Error(c.OIDC.RoleClaimPath)
	}
}

func TestRefusals(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	base := f.prod("")
	cases := map[string]struct {
		cfg, want string
	}{
		"unknown top key":      {f.prod(`bogus = 1`), "unknown keys: bogus"},
		"unknown nested key":   {strings.Replace(base, "[oidc]", "[oidc]\nclient_secrett = \"x\"", 1), "unknown keys: oidc.client_secrett"},
		"http public prod":     {strings.Replace(base, "https://drop", "http://drop", 1), "https:// in production"},
		"proxy http prod":      {strings.Replace(f.prod(`tls = "proxy"`), "https://drop.example.com", "http://localhost:8080", 1), `tls = "proxy" requires an https://`},
		"acme ip host":         {strings.Replace(base, "drop.example.com", "203.0.113.4", 1), "public DNS name"},
		"public url path":      {strings.Replace(base, "drop.example.com", "drop.example.com/sub", 1), "must not contain a path"},
		"trusted proxy acme":   {f.prod(`trusted_proxies = ["10.0.0.0/8"]`), "only valid with tls"},
		"bad cidr":             {f.prod(`tls = "proxy"` + "\n" + `trusted_proxies = ["10.0.0.0/33"]`), "invalid CIDR"},
		"unix in acme":         {f.prod(`listen = "unix:/run/d.sock"`), "unix: listen socket"},
		"secret in prod":       {strings.Replace(base, `client_key_file = "`+f.keyCert+`"`, `client_auth = "client_secret"`+"\n"+`client_secret_file = "`+f.secret+`"`, 1), "only allowed in dev mode"},
		"common issuer":        {strings.Replace(base, "11111111-2222-3333-4444-555555555555/v2.0", "common/v2.0", 1), "multi-tenant"},
		"organizations issuer": {strings.Replace(base, "11111111-2222-3333-4444-555555555555/v2.0", "organizations/v2.0", 1), "multi-tenant"},
		"consumers issuer":     {strings.Replace(base, "11111111-2222-3333-4444-555555555555/v2.0", "consumers/v2.0", 1), "multi-tenant"},
		"templated issuer":     {strings.Replace(base, "11111111-2222-3333-4444-555555555555/v2.0", "{tenantid}/v2.0", 1), "templated"},
		"tid mismatch":         {strings.Replace(base, `tid = "11111111`, `tid = "99999999`, 1), "does not match"},
		"http issuer prod":     {strings.Replace(base, "https://login.microsoftonline.com", "http://localhost", 1), "oidc.issuer must be https"},
		"too large":            {f.prod("[limits]\nmax_file_size = \"101GB\""), "max_file_size"},
		"bad expiry":           {f.prod("[limits]\ndefault_expiry = \"2d\""), "default_expiry"},
		"no openid":            {strings.Replace(base, "[oidc]", "[oidc]\nscopes = [\"profile\"]", 1), `include "openid"`},
		"override iss":         {strings.Replace(base, "tid = ", "iss = \"x\", tid = ", 1), "registered claim"},
		"revalidate too slow":  {strings.Replace(base, "[oidc]", "[oidc]\nrevalidate_every = \"2h\"", 1), "revalidate_every"},
		"bad mode":             {f.prod(`mode = "staging"`), "mode must be"},
		"bad role path":        {strings.Replace(base, "[oidc]", "[oidc]\nrole_claim = \"a..b\"", 1), "role_claim"},
		// Audit L-1.
		"proxy without trusted_proxies": {f.prod(`tls = "proxy"`), "needs trusted_proxies"},
		"unix proxy without trust":      {f.prod(`tls = "proxy"` + "\n" + `listen = "unix:/run/d.sock"`), "trust_unix_socket_proxy = true"},
		"unix trust on tcp":             {f.prod(`tls = "proxy"` + "\n" + `trust_unix_socket_proxy = true`), "only valid with a unix: listen"},
		"unix trust in acme":            {f.prod(`trust_unix_socket_proxy = true`), "only valid with tls"},
		// Audit L-4.
		"per-ip above total": {f.prod("[limits]\nmax_transfers = 4\nmax_transfers_per_ip = 8"), "max_transfers"},
		"negative transfers": {f.prod("[limits]\nmax_transfers = -1"), "max_transfers"},
		"bad min rate":       {f.prod("[limits]\nmin_transfer_rate = \"fast\""), "min_transfer_rate"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte(tc.cfg))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestRefreshKeyFormats(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	ok := map[string][]byte{
		"raw":    raw,
		"std":    []byte(base64.StdEncoding.EncodeToString(raw) + "\n"),
		"rawurl": []byte(base64.RawURLEncoding.EncodeToString(raw)),
	}
	for name, data := range ok {
		p := filepath.Join(dir, name)
		write(t, p, data)
		k, err := LoadRefreshKey(p)
		if err != nil || !bytes.Equal(k, raw) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, data := range map[string][]byte{
		"short":  raw[:31],
		"b64-16": []byte(base64.StdEncoding.EncodeToString(raw[:16])),
		"empty":  nil,
	} {
		p := filepath.Join(dir, name)
		write(t, p, data)
		if _, err := LoadRefreshKey(p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := LoadRefreshKey(dir); err == nil {
		t.Error("directory accepted")
	}
}

func TestClientKeyParsing(t *testing.T) {
	t.Parallel()
	small, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // testing rejection of weak keys
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(small)
	if _, err := ParseClientKey(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})); err == nil {
		t.Error("1024-bit RSA accepted")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ = x509.MarshalECPrivateKey(p384)
	if _, err := ParseClientKey(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err == nil {
		t.Error("P-384 accepted")
	}
	if _, err := ParseClientKey([]byte("garbage")); err == nil {
		t.Error("garbage accepted")
	}
	if _, err := ParseClientKey(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}})); err == nil {
		t.Error("encrypted accepted")
	}

	// Certificate that does not match the key.
	f := newFixture(t)
	certPEM, _ := os.ReadFile(f.keyCert)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ = x509.MarshalPKCS8PrivateKey(other)
	_, certOnly, _ := strings.Cut(string(certPEM), "-----END PRIVATE KEY-----\n")
	mismatch := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})) + certOnly
	if _, err := ParseClientKey([]byte(mismatch)); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("mismatch: %v", err)
	}
	if err := checkAlgForKey("RS256", other); err == nil {
		t.Error("RS256 with EC key accepted")
	}
}

func TestParseSize(t *testing.T) {
	t.Parallel()
	good := map[string]int64{
		"5GB": 5 * GiB, "5gb": 5 * GiB, "100GB": MaxFileSizeCap, "512MiB": 512 * MiB,
		"1024": 1024, "10 KB": 10 * KiB, "1T": TiB, "0": 0, "7B": 7,
	}
	for in, want := range good {
		got, err := ParseSize(in)
		if err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "GB", "-1GB", "+1GB", "1.5GB", "5XB", "99999999999999TB", "1e3"} {
		if _, err := ParseSize(in); err == nil {
			t.Errorf("ParseSize(%q) accepted", in)
		}
	}
}

func TestParseDuration(t *testing.T) {
	t.Parallel()
	good := map[string]time.Duration{"15m": 15 * time.Minute, "7d": 7 * 24 * time.Hour, "1h30m": 90 * time.Minute, "0d": 0}
	for in, want := range good {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "d", "-1d", "+1d", "-5m", "1.5d", "abc", "99999999999999999d"} {
		if _, err := ParseDuration(in); err == nil {
			t.Errorf("ParseDuration(%q) accepted", in)
		}
	}
}

func FuzzParseSize(f *testing.F) {
	for _, s := range []string{"5GB", "100GiB", "1", "-1", "9223372036854775807", "8EB"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := ParseSize(s)
		if err == nil && n < 0 {
			t.Fatalf("negative size %d from %q", n, s)
		}
	})
}

func FuzzParseDuration(f *testing.F) {
	for _, s := range []string{"7d", "15m", "-1h", "9999999999d"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := ParseDuration(s)
		if err == nil && d < 0 {
			t.Fatalf("negative duration %v from %q", d, s)
		}
	})
}

// The shipped example and dev configs must stay valid (strict keys, rules).
func TestShippedConfigs(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"../../deploy/dropr.example.toml", "../../deploy/dropr.dev.toml"} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var c Config
		md, err := toml.Decode(string(data), &c)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if und := md.Undecoded(); len(und) > 0 {
			t.Fatalf("%s: unknown keys %v", p, und)
		}
		c.applyDefaults()
		if err := c.validate(); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
}

// Audit L-1: proxy mode with a known proxy address, or an explicitly
// trusted unix socket, starts; dev mode only warns without either.
func TestProxyTrust(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for name, extra := range map[string]string{
		"tcp with trusted proxy": `tls = "proxy"` + "\n" + `trusted_proxies = ["127.0.0.1"]`,
		"unix trusted":           `tls = "proxy"` + "\n" + `listen = "unix:/run/d.sock"` + "\n" + `trust_unix_socket_proxy = true`,
		"unix with proxies":      `tls = "proxy"` + "\n" + `listen = "unix:/run/d.sock"` + "\n" + `trusted_proxies = ["10.0.0.0/8"]`,
	} {
		if c, err := Parse([]byte(f.prod(extra))); err != nil || len(c.Warnings) != 0 {
			t.Errorf("%s: %v %v", name, err, c)
		}
	}
	c, err := Parse([]byte(strings.Replace(f.prod(`tls = "proxy"`+"\n"+`mode = "dev"`), "https://drop.example.com", "http://localhost:8080", 1)))
	if err != nil || len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "trusted_proxies") {
		t.Fatalf("dev proxy without trusted_proxies: %v %v", err, c)
	}
}

// Audit I-7: secret files readable by others refuse production, readable
// by the group warn, and managed secret directories are exempt.
func TestSecretFilePermissions(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	if err := os.Chmod(f.refresh, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]byte(f.prod(""))); err == nil || !strings.Contains(err.Error(), "readable by every user") {
		t.Fatalf("world-readable refresh key in production: %v", err)
	}
	if err := os.Chmod(f.refresh, 0o640); err != nil {
		t.Fatal(err)
	}
	c, err := Parse([]byte(f.prod("")))
	if err != nil || len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "group or others") {
		t.Fatalf("group-readable refresh key: %v %v", err, c)
	}
	if w, err := checkSecretPerms("/run/secrets/refresh_key", true); w != "" || err != nil {
		t.Errorf("managed secret checked: %q %v", w, err)
	}
	dev := `mode = "dev"` + "\n" + `tls = "proxy"` + "\n" + `trusted_proxies = ["127.0.0.1"]`
	if err := os.Chmod(f.refresh, 0o644); err != nil {
		t.Fatal(err)
	}
	c, err = Parse([]byte(strings.Replace(f.prod(dev), "https://drop.example.com", "http://localhost:8080", 1)))
	if err != nil || len(c.Warnings) != 1 {
		t.Fatalf("world-readable in dev must only warn: %v %v", err, c)
	}
}

// Audit L-4: transfer limits default sensibly and parse.
func TestTransferLimits(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c, err := Parse([]byte(f.prod("")))
	if err != nil || c.Limits.MaxTransfers != 512 || c.Limits.MaxTransfersPerIP != 32 || c.Limits.MinTransferRateBytes != 4*KiB {
		t.Fatalf("defaults: %v %+v", err, c)
	}
	c, err = Parse([]byte(f.prod("[limits]\nmax_transfers = 8\nmax_transfers_per_ip = 2\nmin_transfer_rate = \"0\"")))
	if err != nil || c.Limits.MaxTransfers != 8 || c.Limits.MaxTransfersPerIP != 2 || c.Limits.MinTransferRateBytes != 0 {
		t.Fatalf("custom: %v %+v", err, c)
	}
}
