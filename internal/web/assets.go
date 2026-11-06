package web

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"
)

// ManifestName is the build manifest written by the TypeScript build into
// internal/web/static. It maps logical asset names to content-hashed file
// names relative to the static directory, e.g.
//
//	{"dashboard.js": "dashboard-5KQ2ZJ3C.js", "sw.js": "sw.js"}
//
// Files not listed (hand-written ones such as app.css) are fingerprinted at
// startup from their SHA-256. A missing manifest is fine (dev, or before the
// first TS build).
const ManifestName = "manifest.json"

// ServiceWorkerName is the logical name of the service worker, served from
// /sw.js so its scope can be "/".
const ServiceWorkerName = "sw.js"

// Asset is one embedded static file.
type Asset struct {
	Logical     string
	Public      string // URL path below /assets/
	Data        []byte
	ETag        string
	Integrity   string // Subresource Integrity value (sha384)
	ContentType string
}

// Assets indexes the embedded static files.
type Assets struct {
	byLogical map[string]*Asset
	byPublic  map[string]*Asset
}

// LoadAssets reads every file of fsys (rooted at the static directory).
func LoadAssets(fsys fs.FS) (*Assets, error) {
	manifest := map[string]string{}
	if raw, err := fs.ReadFile(fsys, ManifestName); err == nil {
		if err := json.Unmarshal(raw, &manifest); err != nil {
			return nil, fmt.Errorf("web: %s: %w", ManifestName, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	hashedToLogical := map[string]string{}
	for logical, file := range manifest {
		if !validAssetPath(logical) || !validAssetPath(file) {
			return nil, fmt.Errorf("web: %s: invalid entry %q -> %q", ManifestName, logical, file)
		}
		hashedToLogical[file] = logical
	}

	a := &Assets{byLogical: map[string]*Asset{}, byPublic: map[string]*Asset{}}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || p == ManifestName {
			return err
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		sri := sha512.Sum384(data)
		as := &Asset{
			Data:        data,
			ETag:        `"` + hex.EncodeToString(sum[:16]) + `"`,
			Integrity:   "sha384-" + base64.StdEncoding.EncodeToString(sri[:]),
			ContentType: contentType(p),
		}
		if logical, ok := hashedToLogical[p]; ok {
			as.Logical, as.Public = logical, p
		} else {
			as.Logical, as.Public = p, fingerprint(p, hex.EncodeToString(sum[:5]))
		}
		if prev, dup := a.byLogical[as.Logical]; dup && prev.Public != as.Public {
			// A manifest entry wins over an unhashed file of the same name.
			if _, fromManifest := hashedToLogical[p]; !fromManifest {
				a.byPublic[as.Public] = as
				return nil
			}
		}
		a.byLogical[as.Logical] = as
		a.byPublic[as.Public] = as
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("web: load assets: %w", err)
	}
	for logical, file := range manifest {
		if _, ok := a.byPublic[file]; !ok {
			return nil, fmt.Errorf("web: %s lists %q -> %q but the file is missing", ManifestName, logical, file)
		}
	}
	return a, nil
}

func validAssetPath(p string) bool {
	return p != "" && fs.ValidPath(p) && !strings.Contains(p, "\\") && path.Clean(p) == p
}

// fingerprint inserts a content hash before the extension: app.css ->
// app.3f2a1b4c5d.css.
func fingerprint(p, hash string) string {
	ext := path.Ext(p)
	return strings.TrimSuffix(p, ext) + "." + hash + ext
}

var contentTypes = map[string]string{
	".css":         "text/css; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".map":         "application/json; charset=utf-8",
	".json":        "application/json; charset=utf-8",
	".webmanifest": "application/manifest+json; charset=utf-8",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".ico":         "image/x-icon",
	".woff2":       "font/woff2",
	".txt":         "text/plain; charset=utf-8",
	".wasm":        "application/wasm",
}

func contentType(p string) string {
	ext := strings.ToLower(path.Ext(p))
	// Only an explicit allowlist: anything else is served as an opaque
	// download type so no embedded file can ever be rendered as a document.
	if ct, ok := contentTypes[ext]; ok {
		return ct
	}
	return "application/octet-stream"
}

// URL returns the public URL of a logical asset.
func (a *Assets) URL(logical string) (string, error) {
	as, ok := a.byLogical[logical]
	if !ok {
		return "", fmt.Errorf("web: unknown asset %q", logical)
	}
	return "/assets/" + as.Public, nil
}

// Integrity returns the SRI value of a logical asset.
func (a *Assets) Integrity(logical string) (string, error) {
	as, ok := a.byLogical[logical]
	if !ok {
		return "", fmt.Errorf("web: unknown asset %q", logical)
	}
	return as.Integrity, nil
}

// Hashes lists "integrity  /assets/public" lines for publication (PLAN.md §7
// "published asset hashes").
func (a *Assets) Hashes() []string {
	out := make([]string, 0, len(a.byPublic))
	for p, as := range a.byPublic {
		out = append(out, as.Integrity+"  /assets/"+p)
	}
	sort.Strings(out)
	return out
}

var assetEpoch = time.Unix(0, 0)

// Handler serves GET /assets/{path...} with immutable caching. Unknown names
// go to notFound.
func (a *Assets) Handler(notFound http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		as, ok := a.byPublic[r.PathValue("path")]
		if !ok {
			notFound.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		h.Set("Content-Type", as.ContentType)
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
		h.Set("ETag", as.ETag)
		http.ServeContent(w, r, "", assetEpoch, bytes.NewReader(as.Data))
	})
}

// ServiceWorkerHandler serves /sw.js with Service-Worker-Allowed: /_dl/ (the
// only scope it is registered with; a root-scope registration is refused,
// audit I-1) and revalidation on every load, so service worker updates apply promptly.
func (a *Assets) ServiceWorkerHandler(notFound http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		as, ok := a.byLogical[ServiceWorkerName]
		if !ok {
			notFound.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "text/javascript; charset=utf-8")
		h.Set("Service-Worker-Allowed", "/_dl/")
		h.Set("Cache-Control", "no-cache")
		h.Set("ETag", as.ETag)
		http.ServeContent(w, r, "", assetEpoch, bytes.NewReader(as.Data))
	})
}
