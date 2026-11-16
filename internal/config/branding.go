package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/scttpr/dropr/internal/textclean"
)

// DefaultBrandName is the name shown when [branding] sets none.
const DefaultBrandName = "Dropr"

const (
	maxBrandName = 40        // runes, after cleaning
	maxBrandFile = 256 << 10 // bytes
)

// Branding is the instance's name and logos (DESIGN.md §9), set at deploy
// time. The files are read once at startup.
type Branding struct {
	Name         string `toml:"name"`
	LogoFile     string `toml:"logo_file"`
	LogoDarkFile string `toml:"logo_dark_file"`
	FaviconFile  string `toml:"favicon_file"`

	// Derived: the files' contents, nil when not configured.
	Logo     *BrandFile `toml:"-"`
	LogoDark *BrandFile `toml:"-"`
	Favicon  *BrandFile `toml:"-"`
}

// BrandFile is a loaded logo or favicon.
type BrandFile struct {
	Data        []byte
	ContentType string // image/svg+xml, image/png or image/webp
	Ext         string // svg, png or webp
}

// Custom reports whether the instance shows anything other than Dropr's own
// name and logo.
func (b *Branding) Custom() bool {
	return b.Name != DefaultBrandName || b.LogoFile != "" || b.LogoDarkFile != "" || b.FaviconFile != ""
}

func (c *Config) validateBranding(fail func(string, ...any)) {
	b := &c.Branding
	b.Name = textclean.DisplayText(b.Name)
	if n := utf8.RuneCountInString(b.Name); n < 1 || n > maxBrandName {
		fail("branding.name must be 1-%d visible characters", maxBrandName)
	}
	if b.LogoDarkFile != "" && b.LogoFile == "" {
		fail("branding.logo_dark_file needs branding.logo_file")
	}
}

// loadBranding reads the brand files. They are not secrets: their
// permissions are not checked.
func (c *Config) loadBranding() error {
	b := &c.Branding
	for _, f := range []struct {
		key, path string
		dst       **BrandFile
	}{
		{"branding.logo_file", b.LogoFile, &b.Logo},
		{"branding.logo_dark_file", b.LogoDarkFile, &b.LogoDark},
		{"branding.favicon_file", b.FaviconFile, &b.Favicon},
	} {
		if f.path == "" {
			continue
		}
		bf, warn, err := LoadBrandFile(f.path)
		if err != nil {
			return fmt.Errorf("config: %s: %w", f.key, err)
		}
		if warn != "" {
			c.Warnings = append(c.Warnings, f.key+": "+warn)
		}
		*f.dst = bf
	}
	return nil
}

// LoadBrandFile reads a logo or favicon of at most 256 KiB. The type comes
// from the extension (.svg, .png, .webp) and must match the content. An SVG
// that could run script is refused; one that references external resources
// loads with a warning (they will not load: the page CSP and the SVG's own
// sandbox block them).
func LoadBrandFile(path string) (*BrandFile, string, error) {
	var bf BrandFile
	switch strings.ToLower(filepath.Ext(path)) {
	case ".svg":
		bf.ContentType, bf.Ext = "image/svg+xml", "svg"
	case ".png":
		bf.ContentType, bf.Ext = "image/png", "png"
	case ".webp":
		bf.ContentType, bf.Ext = "image/webp", "webp"
	default:
		return nil, "", errors.New("must be a .svg, .png or .webp file")
	}
	f, err := os.Open(path) //nolint:gosec // operator-supplied branding path
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil {
		return nil, "", err
	} else if !st.Mode().IsRegular() {
		return nil, "", errors.New("not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBrandFile+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > maxBrandFile {
		return nil, "", fmt.Errorf("larger than %d KiB", maxBrandFile>>10)
	}
	bf.Data = data
	var warn string
	switch bf.Ext {
	case "png":
		if !bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) {
			return nil, "", errors.New("content is not PNG")
		}
	case "webp":
		if len(data) < 12 || string(data[:4]) != "RIFF" || string(data[8:12]) != "WEBP" {
			return nil, "", errors.New("content is not WebP")
		}
	case "svg":
		if warn, err = checkSVG(data); err != nil {
			return nil, "", err
		}
	}
	return &bf, warn, nil
}

var (
	// svgProlog matches what may precede the root element: whitespace, the
	// XML declaration, comments and a DOCTYPE without internal subset.
	svgProlog = regexp.MustCompile(`^(?:\s+|<\?xml[^>]*\?>|<!--(?:[^-]|-[^-])*-->|<!doctype[^>\[]*>)*`)
	// charRef is a numeric character reference, decoded before the checks
	// so it cannot hide a forbidden name.
	charRef = regexp.MustCompile(`&#(x[0-9a-f]+|[0-9]+);?`)
	// svgEvent is an event handler attribute (onload=, onclick=…).
	svgEvent = regexp.MustCompile(`[\s"'/]on[a-z]+\s*=`)
	// svgExternal is a reference to a remote resource.
	svgExternal = regexp.MustCompile(`(?:href\s*=|url\(|@import)\s*["']?\s*(?:https?:)?//`)
	// svgForbidden are the elements and schemes that can carry script or
	// HTML.
	svgForbidden = []string{"<script", "<foreignobject", "<iframe", "<embed", "<object", "<handler", "<!entity", "javascript:"}
)

// checkSVG refuses an SVG that could run script (in every mode) and returns
// a warning when it references remote resources.
func checkSVG(data []byte) (string, error) {
	if !utf8.Valid(data) {
		return "", errors.New("SVG is not valid UTF-8")
	}
	text := strings.ToLower(strings.TrimPrefix(string(data), "\ufeff"))
	if !strings.HasPrefix(text[len(svgProlog.FindString(text)):], "<svg") {
		return "", errors.New("content is not SVG (no <svg> root element)")
	}
	text = charRef.ReplaceAllStringFunc(text, func(m string) string {
		num := strings.TrimSuffix(strings.TrimPrefix(m, "&#"), ";")
		base := 10
		if strings.HasPrefix(num, "x") {
			num, base = num[1:], 16
		}
		r, err := strconv.ParseInt(num, base, 32)
		if err != nil || !utf8.ValidRune(rune(r)) {
			return "\ufffd"
		}
		return strings.ToLower(string(rune(r)))
	})
	// Browsers ignore tabs and newlines inside a URL scheme.
	squeezed := strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(text)
	for _, bad := range svgForbidden {
		if strings.Contains(squeezed, bad) {
			return "", fmt.Errorf("SVG contains %q, which can run script: remove it", bad)
		}
	}
	if svgEvent.MatchString(text) {
		return "", errors.New("SVG has an event handler attribute (on…=), which can run script: remove it")
	}
	if svgExternal.MatchString(squeezed) {
		return "SVG references remote resources; they will not load (keep everything inside the file)", nil
	}
	return "", nil
}
