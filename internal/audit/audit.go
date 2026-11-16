// Package audit names the log events an operator can rely on
// (ARCHITECTURE.md §5, Logging) and derives the keyed references that stand
// in for link and file IDs in logs.
//
// Link, file, upload and token IDs are capabilities: whoever reads one from
// a log could exhaust a share link or fill a request link. Logs therefore
// carry a reference instead, a truncated HMAC of the ID under a key derived
// from the instance's refresh_key (`dropr log-ref` computes it from an ID).
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"

	"github.com/scttpr/dropr/internal/seal"
)

// Event names, the value of the "event" attribute. They are a stable
// interface: rename one only with a release note.
const (
	ShareCreated    = "share.created"
	ShareReady      = "share.ready"      // last part finalized
	ShareOpened     = "share.opened"     // download token issued (not counted)
	ShareDownloaded = "share.downloaded" // first byte-serving GET of a token: counted
	ShareExhausted  = "share.exhausted"  // the counted download reached max_downloads
	ShareRevoked    = "share.revoked"
	RequestCreated  = "request.created"
	RequestUpload   = "request.upload_started"
	RequestReceived = "request.file_received"
	RequestClosed   = "request.closed"
	RequestRevoked  = "request.revoked"
	InboxDownload   = "inbox.download_requested"
	InboxDeleted    = "inbox.deleted"
	LinkPurged      = "link.purged"
	UserLogin       = "auth.login"
	UserDenied      = "auth.denied"
	UserLogout      = "auth.logout"
	UserAccessLost  = "user.access_lost"
	SessionEnded    = "session.ended" // failed revalidation
)

// Event returns the "event" attribute of a log line.
func Event(name string) slog.Attr { return slog.String("event", name) }

// refBytes is the length of a reference before hex encoding: 48 bits, 12
// hex characters. Enough to tell an instance's links apart in logs, far too
// short to stand for the ID.
const refBytes = 6

// Refs derives log references.
type Refs struct{ key []byte }

// NewRefs returns the reference deriver for key (seal.InfoLogRef subkey of
// the refresh_key).
func NewRefs(key []byte) *Refs { return &Refs{key: append([]byte(nil), key...)} }

// RefsFor returns the reference deriver of an instance from its 32-byte
// refresh_key. The server and `dropr log-ref` both use it, so a reference
// computed by hand matches the logs; a new refresh_key changes every
// reference.
func RefsFor(refreshKey []byte) (*Refs, error) {
	key, err := seal.Derive(refreshKey, seal.InfoLogRef)
	if err != nil {
		return nil, err
	}
	return NewRefs(key), nil
}

// Link returns the reference of a share or request ID.
func (r *Refs) Link(id string) string { return r.ref("link", id) }

// File returns the reference of an inbox file ID.
func (r *Refs) File(id string) string { return r.ref("file", id) }

// Purge kinds, the "kind" attribute of link.purged.
const (
	KindShare   = "share"
	KindRequest = "request"
)

// PurgeLogger returns the callback that logs a link deleted by the expiry
// cleanup (jobs.FileTasks).
func PurgeLogger(log *slog.Logger, refs *Refs) func(ctx context.Context, kind, id string) {
	return func(ctx context.Context, kind, id string) {
		log.InfoContext(ctx, "link purged", Event(LinkPurged), "kind", kind, "link", refs.Link(id), "reason", "expired")
	}
}

func (r *Refs) ref(domain, id string) string {
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte(domain))
	m.Write([]byte{0})
	m.Write([]byte(id))
	return hex.EncodeToString(m.Sum(nil)[:refBytes])
}
