package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // x5t is a certificate identifier, not a security function
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/scttpr/dropr/internal/ids"
)

// ClientAssertionType is the RFC 7523 assertion type for private_key_jwt.
const ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// assertionLifetime is the validity of a client assertion. RFC 7523 leaves it
// to the server; providers commonly cap it (Entra: 10 min). Short is better.
const assertionLifetime = 2 * time.Minute

var b64 = base64.RawURLEncoding

// assertionSigner produces private_key_jwt client assertions (RFC 7523 §2.2,
// OIDC Core §9).
//
// Header:
//   - alg: RS256, PS256 or ES256.
//   - kid: when configured (Keycloak and most providers match keys by kid).
//   - x5t#S256: SHA-256 thumbprint of the certificate when one is provided.
//     Microsoft Entra ID identifies the certificate credential through the
//     x5t#S256 header (with PS256, its recommended combination) or the legacy
//     SHA-1 x5t header; it does not use kid. x5t can be enabled with
//     client_assertion_x5t_sha1 for setups that still need it.
//
// Claims: iss = sub = client_id, aud = token endpoint, a unique jti, iat, nbf
// and exp (2 minutes, well under the common 5-10 minute caps).
type assertionSigner struct {
	key      crypto.Signer
	alg      string
	kid      string
	x5tS256  string
	x5t      string
	clientID string
}

func newAssertionSigner(key crypto.Signer, cert *x509.Certificate, alg, kid, clientID string, withSHA1 bool) (*assertionSigner, error) {
	a := &assertionSigner{key: key, alg: alg, kid: kid, clientID: clientID}
	switch key.(type) {
	case *rsa.PrivateKey:
		if alg != "RS256" && alg != "PS256" {
			return nil, fmt.Errorf("oidc: alg %s does not match RSA key", alg)
		}
	case *ecdsa.PrivateKey:
		if alg != "ES256" {
			return nil, fmt.Errorf("oidc: alg %s does not match EC key", alg)
		}
	default:
		return nil, fmt.Errorf("oidc: unsupported client key %T", key)
	}
	if cert != nil {
		s := sha256.Sum256(cert.Raw)
		a.x5tS256 = b64.EncodeToString(s[:])
		if withSHA1 {
			h := sha1.Sum(cert.Raw) //nolint:gosec // identifier only, see above
			a.x5t = b64.EncodeToString(h[:])
		}
	}
	return a, nil
}

// chooseAssertionAlg picks the signing algorithm: the configured one if set,
// otherwise the first of the key's candidates the provider advertises (or the
// preferred one when the provider does not advertise a list).
func chooseAssertionAlg(configured string, key crypto.Signer, advertised []string) (string, error) {
	var candidates []string
	switch key.(type) {
	case *rsa.PrivateKey:
		candidates = []string{"PS256", "RS256"}
	case *ecdsa.PrivateKey:
		candidates = []string{"ES256"}
	default:
		return "", fmt.Errorf("oidc: unsupported client key %T", key)
	}
	if configured != "" {
		if !slices.Contains(candidates, configured) {
			return "", fmt.Errorf("oidc: client_assertion_alg %s does not match the key type", configured)
		}
		if len(advertised) > 0 && !slices.Contains(advertised, configured) {
			return "", fmt.Errorf("oidc: provider does not accept %s client assertions (supports %v)", configured, advertised)
		}
		return configured, nil
	}
	if len(advertised) == 0 {
		return candidates[0], nil
	}
	for _, c := range candidates {
		if slices.Contains(advertised, c) {
			return c, nil
		}
	}
	return "", fmt.Errorf("oidc: provider accepts none of %v for client assertions (supports %v)", candidates, advertised)
}

// sign returns a compact JWS client assertion for the given audience.
func (a *assertionSigner) sign(aud string, now time.Time) (string, error) {
	hdr := map[string]string{"alg": a.alg, "typ": "JWT"}
	if a.kid != "" {
		hdr["kid"] = a.kid
	}
	if a.x5tS256 != "" {
		hdr["x5t#S256"] = a.x5tS256
	}
	if a.x5t != "" {
		hdr["x5t"] = a.x5t
	}
	claims := map[string]any{
		"iss": a.clientID,
		"sub": a.clientID,
		"aud": aud,
		"jti": ids.NewSecret(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(assertionLifetime).Unix(),
	}
	h, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
	sig, err := signJWS(a.key, a.alg, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64.EncodeToString(sig), nil
}

func signJWS(key crypto.Signer, alg string, input []byte) ([]byte, error) {
	digest := sha256.Sum256(input)
	switch alg {
	case "RS256":
		return key.Sign(rand.Reader, digest[:], crypto.SHA256)
	case "PS256":
		return key.Sign(rand.Reader, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	case "ES256":
		der, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return nil, err
		}
		var sig struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(der, &sig)
		if err != nil || len(rest) > 0 {
			return nil, errors.New("oidc: malformed ECDSA signature")
		}
		out := make([]byte, 64)
		sig.R.FillBytes(out[:32])
		sig.S.FillBytes(out[32:])
		return out, nil
	default:
		return nil, fmt.Errorf("oidc: unsupported alg %s", alg)
	}
}
