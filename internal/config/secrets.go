package config

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxSecretFile = 64 << 10

func readSecretFile(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("no file configured")
	}
	f, err := os.Open(path) //nolint:gosec // operator-supplied secret path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSecretFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSecretFile {
		return nil, fmt.Errorf("%s is too large", path)
	}
	return data, nil
}

// LoadRefreshKey reads the 32-byte master key. The file holds either exactly
// 32 raw bytes or the base64 (standard or URL alphabet, padding optional)
// encoding of 32 bytes, optionally followed by a newline.
func LoadRefreshKey(path string) ([]byte, error) {
	data, err := readSecretFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 32 {
		return data, nil
	}
	s := strings.TrimSpace(string(data))
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if k, err := enc.Strict().DecodeString(s); err == nil && len(k) == 32 {
			return k, nil
		}
	}
	return nil, errors.New("must contain 32 random bytes, raw or base64 (generate with: openssl rand -base64 32)")
}

// LoadSecretFile reads a text secret (e.g. a dev client secret), trimming a
// trailing newline.
func LoadSecretFile(path string) (string, error) {
	data, err := readSecretFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimRight(string(data), "\r\n")
	if s == "" || strings.ContainsAny(s, "\r\n") {
		return "", errors.New("must contain a single non-empty line")
	}
	return s, nil
}

// ClientKey is the private_key_jwt signing key with its optional certificate.
type ClientKey struct {
	Key   crypto.Signer
	Cert  *x509.Certificate   // leaf certificate, if present
	Chain []*x509.Certificate // all certificates in file order
}

// LoadClientKey reads a PEM file holding one unencrypted private key (PKCS#8,
// PKCS#1 RSA or SEC1 EC) and optionally certificates. When certificates are
// present, the first one must match the private key.
func LoadClientKey(path string) (*ClientKey, error) {
	data, err := readSecretFile(path)
	if err != nil {
		return nil, err
	}
	return ParseClientKey(data)
}

// ParseClientKey is LoadClientKey for in-memory PEM.
func ParseClientKey(data []byte) (*ClientKey, error) {
	var ck ClientKey
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse certificate: %w", err)
			}
			ck.Chain = append(ck.Chain, c)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			if ck.Key != nil {
				return nil, errors.New("more than one private key")
			}
			k, err := parsePrivateKey(block)
			if err != nil {
				return nil, err
			}
			ck.Key = k
		case "ENCRYPTED PRIVATE KEY":
			return nil, errors.New("encrypted private keys are not supported; protect the file with permissions instead")
		case "EC PARAMETERS":
			// Emitted by `openssl ecparam -genkey`; harmless.
		default:
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("trailing non-PEM data")
	}
	if ck.Key == nil {
		return nil, errors.New("no private key found")
	}
	if len(ck.Chain) > 0 {
		ck.Cert = ck.Chain[0]
		pub, ok := ck.Cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
		if !ok || !pub.Equal(ck.Key.Public()) {
			return nil, errors.New("certificate does not match the private key")
		}
	}
	return &ck, nil
}

func parsePrivateKey(block *pem.Block) (crypto.Signer, error) {
	var (
		k   any
		err error
	)
	switch block.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	switch key := k.(type) {
	case *rsa.PrivateKey:
		if key.N.BitLen() < 2048 {
			return nil, errors.New("RSA keys must be at least 2048 bits")
		}
		return key, nil
	case *ecdsa.PrivateKey:
		if key.Curve != elliptic.P256() {
			return nil, errors.New("EC keys must use P-256 (ES256)")
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T (use RSA or EC P-256)", k)
	}
}

func checkAlgForKey(alg string, key crypto.Signer) error {
	if alg == "" {
		return nil
	}
	switch key.(type) {
	case *rsa.PrivateKey:
		if alg != "RS256" && alg != "PS256" {
			return fmt.Errorf("%s cannot be used with an RSA key", alg)
		}
	case *ecdsa.PrivateKey:
		if alg != "ES256" {
			return fmt.Errorf("%s cannot be used with an EC key", alg)
		}
	}
	return nil
}

// Directories whose files are managed by the service manager or container
// runtime (systemd credentials, Docker/Podman secrets): their modes are not
// the operator's to tighten (container secrets are often 0444 inside a
// private mount namespace), so they are not checked.
var managedSecretDirs = []string{"/run/credentials/", "/run/secrets/"}

// checkSecretPerms inspects a secret file's mode (audit I-7): readable by
// group or others gives a warning; readable by others refuses to start in
// production. Files under managedSecretDirs are exempt.
func checkSecretPerms(path string, production bool) (warning string, err error) {
	abs, aerr := filepath.Abs(path)
	if aerr == nil {
		for _, d := range managedSecretDirs {
			if strings.HasPrefix(abs, d) {
				return "", nil
			}
		}
	}
	st, serr := os.Stat(path)
	if serr != nil {
		// The loader reports missing or unreadable files.
		return "", nil //nolint:nilerr // reported by the loader
	}
	mode := st.Mode().Perm()
	switch {
	case mode&0o004 != 0 && production:
		return "", fmt.Errorf("%s is readable by every user (mode %#o); run: chmod 600 %s", path, mode, path)
	case mode&0o077 != 0:
		return fmt.Sprintf("secret file %s is readable by group or others (mode %#o); chmod 600 is recommended", path, mode), nil
	}
	return "", nil
}

func (c *Config) checkSecretFiles(paths ...string) error {
	for _, p := range paths {
		if p == "" {
			continue
		}
		w, err := checkSecretPerms(p, c.Production())
		if err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if w != "" {
			c.Warnings = append(c.Warnings, w)
		}
	}
	return nil
}
