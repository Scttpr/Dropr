package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/scttpr/dropr/internal/auth/session"
)

// Revalidation (PLAN.md §5.1): every revalidate_every, the stored refresh
// token is redeemed and the result must pass every login check again, carry
// the same subject and still hold the role. Any failure, including the
// provider being unreachable, kills the session.
//
// Revalidation is lazy: RevalidateMiddleware runs it before serving any
// request whose session is due, so no request is ever served on a session
// that has gone more than revalidate_every without a successful check.
// Requests of one session are serialized during a refresh so a rotating
// refresh token is redeemed exactly once. The lock is the session manager's
// per-session lock, which session rotation also takes (audit L-5), so a
// rotation never copies a refresh token that a concurrent revalidation is
// about to replace.
//
// Refresh responses without an id_token: OIDC Core §12.2 makes the ID token
// optional on refresh. Dropr then calls the userinfo endpoint with the fresh
// access token, requires its sub to equal the account's subject (OIDC Core
// §5.3.4) and applies the role and required_claims checks to the userinfo
// claims. If there is no userinfo endpoint, or it does not return the role
// claim, revalidation fails closed and the session ends. Entra ID and
// Keycloak both return an id_token on refresh when "openid" was requested.

// Revalidate runs revalidation for s if it is due and returns the session to
// continue with (nil if it was killed).
func (p *Provider) Revalidate(ctx context.Context, s *session.Session) (*session.Session, error) {
	if p.now().Sub(s.RevalidatedAt()) < p.cfg.RevalidateDur {
		return s, nil
	}
	unlock := p.sessions.Lock(s)
	defer unlock()

	// Another request may have revalidated (or killed) it while we waited.
	cur, err := p.sessions.Reload(ctx, s)
	if err != nil {
		return nil, err
	}
	if p.now().Sub(cur.RevalidatedAt()) < p.cfg.RevalidateDur {
		return cur, nil
	}
	if err := p.refresh(ctx, cur); err != nil {
		if (errors.Is(err, ErrRoleMissing) || errors.Is(err, ErrClaimMismatch)) && cur.User != nil {
			// The provider withdrew access: request links stop accepting
			// uploads until the next successful login (audit I-3).
			if lerr := p.st.MarkAccessLost(context.WithoutCancel(ctx), cur.User.Issuer, cur.User.Subject, p.now()); lerr != nil {
				err = errors.Join(err, lerr)
			}
		}
		if kerr := p.sessions.Kill(context.WithoutCancel(ctx), cur); kerr != nil {
			return nil, errors.Join(err, kerr)
		}
		return nil, err
	}
	return cur, nil
}

func (p *Provider) refresh(ctx context.Context, s *session.Session) error {
	rt, err := p.sessions.RefreshToken(s)
	if err != nil {
		return err
	}
	if rt == "" {
		return errors.New("oidc: session has no refresh token")
	}
	if s.User == nil || s.User.Issuer != p.cfg.Issuer {
		return errors.New("oidc: account belongs to another issuer")
	}
	tr, err := p.tokenRequest(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
	})
	if err != nil {
		return err
	}
	var id *Identity
	if tr.IDToken != "" {
		id, err = p.verifyIDToken(ctx, tr.IDToken, "", verifyRefresh)
	} else {
		var claims map[string]any
		claims, err = p.fetchUserinfo(ctx, tr.AccessToken)
		if err == nil {
			id, err = p.authorize(p.cfg.Issuer, claims)
		}
	}
	if err != nil {
		return err
	}
	if id.Subject != s.User.Subject {
		return errors.New("oidc: refreshed identity has a different subject")
	}
	return p.sessions.Revalidated(ctx, s, tr.RefreshToken)
}

// RevalidateMiddleware must run after session.Middleware. When the session
// is due it revalidates; on failure the session is ended, its cookie cleared,
// and the request continues as anonymous (handlers then require login).
func (p *Provider) RevalidateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := session.FromContext(r.Context())
		if s == nil {
			next.ServeHTTP(w, r)
			return
		}
		ns, err := p.Revalidate(r.Context(), s)
		if err != nil || ns == nil {
			if err != nil && !errors.Is(err, session.ErrNoSession) {
				p.log.InfoContext(r.Context(), "revalidation failed; session ended", "user", s.UserID(), "reason", err.Error())
			}
			session.ClearCookie(w)
			r = r.WithContext(session.NewContext(r.Context(), nil))
		} else if ns != s {
			r = r.WithContext(session.NewContext(r.Context(), ns))
		}
		next.ServeHTTP(w, r)
	})
}
