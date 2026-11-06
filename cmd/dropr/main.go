// Command dropr is the Dropr server and admin CLI.
//
//	dropr serve   --config dropr.toml
//	dropr user list|revoke|purge|migrate ...
//	dropr gc      --config dropr.toml
//	dropr backup  --config dropr.toml --out FILE
//	dropr healthcheck [--config dropr.toml | --url URL]
//	dropr version
//
// Admin access is shell access to the host; there is no admin web UI.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/scttpr/dropr/internal/auth/session"
	"github.com/scttpr/dropr/internal/blob"
	"github.com/scttpr/dropr/internal/config"
	"github.com/scttpr/dropr/internal/db"
	"github.com/scttpr/dropr/internal/jobs"
	"github.com/scttpr/dropr/internal/server"
	"github.com/scttpr/dropr/internal/store"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

const defaultConfig = "/etc/dropr/dropr.toml"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: dropr <command> [flags]

Commands:
  serve                     run the server
  user list                 list accounts
  user revoke <user>        end all sessions of a user now
  user purge <user>         delete a user and all their data
  user migrate              relink accounts after changing identity provider
  gc                        run the cleanup jobs once
  backup --out FILE         write a consistent online backup of the database
  healthcheck [--url URL]   probe GET /healthz of the local server (exit 0 if healthy)
  version                   print version information

<user> is a user ID or a subject that matches exactly one account.
Every command except version accepts --config (default `+defaultConfig+`).
`)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	var err error
	switch args[0] {
	case "serve":
		err = cmdServe(args[1:], stderr)
	case "user":
		err = cmdUser(args[1:], stdin, stdout, stderr)
	case "gc":
		err = cmdGC(args[1:], stdout, stderr)
	case "backup":
		err = cmdBackup(args[1:], stdout, stderr)
	case "healthcheck":
		err = cmdHealthcheck(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		printVersion(stdout)
	case "help", "-h", "--help":
		usage(stdout)
	default:
		_, _ = fmt.Fprintf(stderr, "dropr: unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		var ue usageError
		if errors.As(err, &ue) {
			_, _ = fmt.Fprintf(stderr, "dropr: %v\n", err)
			return 2
		}
		_, _ = fmt.Fprintf(stderr, "dropr: %v\n", err)
		return 1
	}
	return 0
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func newFlags(name string, stderr io.Writer) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := fs.String("config", defaultConfig, "path to dropr.toml")
	return fs, cfg
}

// parse parses flags allowing them before or after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func newLogger(cfg *config.Config, w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: cfg.Level}))
}

func cmdServe(args []string, stderr io.Writer) error {
	fs, cfgPath := newFlags("serve", stderr)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	log := newLogger(cfg, os.Stdout)
	slog.SetDefault(log)
	log.Info("starting dropr", "version", version, "mode", cfg.Mode)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return server.Run(ctx, cfg, log)
}

// openStore loads the config and opens the database for admin commands.
func openStore(ctx context.Context, cfgPath string) (*config.Config, *db.DB, *store.Store, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, nil, err
	}
	d, err := db.Open(ctx, server.DBPath(cfg))
	if err != nil {
		return nil, nil, nil, err
	}
	return cfg, d, store.New(d), nil
}

func cmdUser(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError{"user: missing subcommand (list, revoke, purge, migrate)"}
	}
	sub, args := args[0], args[1:]
	fs, cfgPath := newFlags("user "+sub, stderr)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	var fromIssuer, toIssuer, mapFile *string
	var dryRun *bool
	if sub == "migrate" {
		fromIssuer = fs.String("from-issuer", "", "issuer the accounts currently belong to (required)")
		toIssuer = fs.String("to-issuer", "", "new issuer (default: oidc.issuer from the config)")
		mapFile = fs.String("map", "", "CSV file of old_subject,new_subject lines (required)")
		dryRun = fs.Bool("dry-run", false, "validate the mapping without changing anything")
	}
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	ctx := context.Background()

	needUser := func() (string, error) {
		if len(pos) != 1 {
			return "", usageError{fmt.Sprintf("user %s: expected exactly one <user> argument", sub)}
		}
		return pos[0], nil
	}

	switch sub {
	case "list":
		if len(pos) != 0 {
			return usageError{"user list: no arguments expected"}
		}
		_, d, st, err := openStore(ctx, *cfgPath)
		if err != nil {
			return err
		}
		defer func() { _ = d.Close() }()
		return listUsers(ctx, st, stdout)

	case "revoke":
		ref, err := needUser()
		if err != nil {
			return err
		}
		_, d, st, err := openStore(ctx, *cfgPath)
		if err != nil {
			return err
		}
		defer func() { _ = d.Close() }()
		u, err := st.FindUser(ctx, ref)
		if err != nil {
			return userErr(ref, err)
		}
		n, err := st.DeleteUserSessions(ctx, u.ID)
		if err != nil {
			return err
		}
		// Their request links stop accepting files until they sign in
		// again with the role (audit I-3).
		if err := st.MarkAccessLostByID(ctx, u.ID, time.Now()); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "Ended %d session(s) of %s (%s); their request links are paused until they sign in again.\n", n, u.ID, displayOf(u))
		return nil

	case "purge":
		ref, err := needUser()
		if err != nil {
			return err
		}
		cfg, d, st, err := openStore(ctx, *cfgPath)
		if err != nil {
			return err
		}
		defer func() { _ = d.Close() }()
		blobs, err := server.NewBlobStore(cfg)
		if err != nil {
			return err
		}
		u, err := st.FindUser(ctx, ref)
		if err != nil {
			return userErr(ref, err)
		}
		warn := fmt.Sprintf("This permanently deletes %s (%s) and ALL their files and links.", u.ID, displayOf(u))
		if !*yes && !confirm(stdin, stdout, warn) {
			return errors.New("aborted")
		}
		ids, err := st.DeleteUser(ctx, u.ID)
		if err != nil {
			return err
		}
		if err := removeBlobs(blobs, ids); err != nil {
			return fmt.Errorf("purged %s, but some files remain (run `dropr gc`): %w", u.ID, err)
		}
		_, _ = fmt.Fprintf(stdout, "Purged %s and deleted %d file(s).\n", u.ID, len(ids))
		return nil

	case "migrate":
		if len(pos) != 0 {
			return usageError{"user migrate: unexpected arguments"}
		}
		if *fromIssuer == "" || *mapFile == "" {
			return usageError{"user migrate: --from-issuer and --map are required"}
		}
		cfg, d, st, err := openStore(ctx, *cfgPath)
		if err != nil {
			return err
		}
		defer func() { _ = d.Close() }()
		to := *toIssuer
		if to == "" {
			to = cfg.OIDC.Issuer
		}
		if to == *fromIssuer {
			return usageError{"user migrate: old and new issuer are identical"}
		}
		f, err := os.Open(*mapFile) //nolint:gosec // admin-supplied path
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		mappings, err := readMapping(f)
		if err != nil {
			return err
		}
		if *dryRun {
			for _, m := range mappings {
				if _, err := st.UserByIdentity(ctx, *fromIssuer, m.OldSubject); err != nil {
					return userErr(m.OldSubject, err)
				}
			}
			_, _ = fmt.Fprintf(stdout, "Dry run: %d mapping(s) valid for %s -> %s.\n", len(mappings), *fromIssuer, to)
			return nil
		}
		if !*yes && !confirm(stdin, stdout, fmt.Sprintf("Relink %d account(s) from %s to %s? Their sessions end.", len(mappings), *fromIssuer, to)) {
			return errors.New("aborted")
		}
		n, err := st.MigrateIdentities(ctx, *fromIssuer, to, mappings)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "Relinked %d account(s).\n", n)
		return nil

	default:
		return usageError{fmt.Sprintf("user: unknown subcommand %q", sub)}
	}
}

func listUsers(ctx context.Context, st *store.Store, stdout io.Writer) error {
	users, err := st.ListUsers(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tNAME\tSUBJECT\tCREATED\tSESSIONS\tISSUER")
	for i := range users {
		u := &users[i]
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n", u.ID, sanitize(u.DisplayName), sanitize(u.Subject),
			u.CreatedAt.Format(time.DateOnly), u.Sessions, sanitize(u.Issuer))
	}
	return tw.Flush()
}

// sanitize strips control characters from provider-supplied strings before
// they reach the admin's terminal.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
}

func displayOf(u *store.User) string {
	if u.DisplayName != "" {
		return sanitize(u.DisplayName)
	}
	return sanitize(u.Subject)
}

func userErr(ref string, err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no user matches %q", sanitize(ref))
	}
	return err
}

func confirm(stdin io.Reader, stdout io.Writer, msg string) bool {
	_, _ = fmt.Fprintf(stdout, "%s\nType \"yes\" to continue: ", msg)
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	return strings.TrimSpace(line) == "yes"
}

// readMapping parses "old_subject,new_subject" lines. Blank lines and lines
// starting with # are ignored, as is a header line "old_subject,new_subject".
func readMapping(r io.Reader) ([]store.IdentityMapping, error) {
	cr := csv.NewReader(r)
	cr.Comment = '#'
	cr.FieldsPerRecord = 2
	cr.TrimLeadingSpace = true
	var out []store.IdentityMapping
	seenOld, seenNew := map[string]bool{}, map[string]bool{}
	for line := 1; ; line++ {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("map: %w", err)
		}
		oldSub, newSub := strings.TrimSpace(rec[0]), strings.TrimSpace(rec[1])
		if len(out) == 0 && oldSub == "old_subject" && newSub == "new_subject" {
			continue
		}
		if oldSub == "" || newSub == "" {
			return nil, fmt.Errorf("map: record %d has an empty subject", line)
		}
		if seenOld[oldSub] || seenNew[newSub] {
			return nil, fmt.Errorf("map: record %d repeats a subject", line)
		}
		seenOld[oldSub], seenNew[newSub] = true, true
		out = append(out, store.IdentityMapping{OldSubject: oldSub, NewSubject: newSub})
	}
	if len(out) == 0 {
		return nil, errors.New("map: no mappings")
	}
	return out, nil
}

func cmdGC(args []string, stdout, stderr io.Writer) error {
	fs, cfgPath := newFlags("gc", stderr)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	ctx := context.Background()
	cfg, d, st, err := openStore(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	log := newLogger(cfg, stderr)
	sessions, err := session.NewManager(st, cfg.RefreshKey, session.Config{}, log)
	if err != nil {
		return err
	}
	r := jobs.NewRunner(0, log)
	var removed int64
	r.Add(jobs.Task{Name: "expired-sessions", Run: func(ctx context.Context) (int64, error) {
		n, err := sessions.Cleanup(ctx)
		removed += n
		return n, err
	}})
	blobs, err := server.NewBlobStore(cfg)
	if err != nil {
		return err
	}
	var files int64
	for _, t := range jobs.FileTasks(st, blobs, nil) {
		run := t.Run
		t.Run = func(ctx context.Context) (int64, error) {
			n, err := run(ctx)
			files += n
			return n, err
		}
		r.Add(t)
	}
	if err := r.RunOnce(ctx); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "Removed %d expired session(s) and %d expired or abandoned item(s).\n", removed, files)
	return nil
}

// removeBlobs deletes the files of blobs whose rows are already gone.
func removeBlobs(blobs *blob.Store, ids []string) error {
	var errs []error
	for _, id := range ids {
		errs = append(errs, blobs.Remove(id))
	}
	return errors.Join(errs...)
}

func cmdBackup(args []string, stdout, stderr io.Writer) error {
	fs, cfgPath := newFlags("backup", stderr)
	out := fs.String("out", "", "destination file (must not exist)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if *out == "" {
		return usageError{"backup: --out is required"}
	}
	ctx := context.Background()
	_, d, _, err := openStore(ctx, *cfgPath)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := d.Backup(ctx, *out); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "Database backed up to %s. Back up the blob directory too.\n", *out)
	return nil
}

func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "dropr %s (%s, %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" || s.Key == "vcs.modified" {
				_, _ = fmt.Fprintf(w, "%s=%s\n", s.Key, s.Value)
			}
		}
	}
	_, _ = fmt.Fprintf(w, "schema version %d\n", db.LatestVersion())
}

// healthTimeout bounds `dropr healthcheck`.
const healthTimeout = 3 * time.Second

// cmdHealthcheck probes GET /healthz of the local server (container
// healthchecks: the distroless image has no shell or curl). With --url it
// probes that URL; otherwise it derives the address from the config's
// listen and tls settings, including Unix sockets. Exit status 0 = healthy.
func cmdHealthcheck(args []string, stdout, stderr io.Writer) error {
	fs, cfgPath := newFlags("healthcheck", stderr)
	rawURL := fs.String("url", "", "probe this URL instead of the configured listener")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthTimeout)
	defer cancel()
	target, client := *rawURL, &http.Client{Timeout: healthTimeout}
	if target == "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		target, client = healthTarget(cfg)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return usageError{fmt.Sprintf("healthcheck: %v", err)}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unhealthy: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: status %d", resp.StatusCode)
	}
	_, _ = fmt.Fprintln(stdout, "ok")
	return nil
}

// healthTarget returns the /healthz URL and client for the configured
// listener. In ACME mode the probe speaks TLS to the local port with the
// public host name as SNI (autocert only answers for it) and does not verify
// the certificate: it checks liveness, not identity.
func healthTarget(cfg *config.Config) (string, *http.Client) {
	tr := &http.Transport{DisableKeepAlives: true}
	client := &http.Client{Timeout: healthTimeout, Transport: tr}
	if path, ok := strings.CutPrefix(cfg.Listen, "unix:"); ok {
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}
		return "http://localhost/healthz", client
	}
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		host, port = "", cfg.Listen
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	addr := net.JoinHostPort(host, port)
	if cfg.TLS == config.TLSACME {
		tr.TLSClientConfig = &tls.Config{ServerName: cfg.Public.Hostname(), InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // liveness probe of our own listener
		return "https://" + addr + "/healthz", client
	}
	return "http://" + addr + "/healthz", client
}
