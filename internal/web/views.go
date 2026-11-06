package web

// Page view models (docs/PAGES.md). Values reach the browser modules only
// through data-* attributes on <main>. Sizes are bytes, times Unix seconds.

// DashboardView is the view model of "/" for a signed-in user.
type DashboardView struct {
	MaxFileSize   int64  // limits.max_file_size, plaintext bytes (data-max-file-size)
	DefaultExpiry string // limits.default_expiry (data-default-expiry)
	// MaxRequestBytes is the default max_bytes of a new request link
	// (data-max-request-bytes): the ciphertext size of one maximal file.
	MaxRequestBytes int64
	InboxCount      int // completely received files
	LinkCount       int // active share and request links
}

// InboxView is the view model of /inbox.
type InboxView struct {
	Count int
}

// LinksView is the view model of /links.
type LinksView struct {
	Count int
}

// ShareView is the view model of a live /s/{id}.
type ShareView struct {
	ID        string // data-share-id
	Size      int64  // ciphertext bytes
	PlainSize int64  // plaintext bytes (exact, FORMAT.md §4.3)
	Parts     int
	ExpiresAt int64 // data-expires-at
}

// RequestView is the view model of a live /r/{id}.
type RequestView struct {
	ID        string // data-request-id
	OwnerName string // "Send a file to …"
	ExpiresAt int64
	// MaxFiles is how many more files the link accepts (data-max-files).
	MaxFiles int64
	// MaxBytes is the largest plaintext the link still accepts in one file
	// (data-max-bytes): what fits in the remaining ciphertext budget, capped
	// at the instance file size limit.
	MaxBytes int64
	// RemainingBytes is the remaining ciphertext budget (max_bytes −
	// bytes_received), the value the server enforces.
	RemainingBytes int64
	MaxFileSize    int64 // limits.max_file_size, plaintext bytes
}
