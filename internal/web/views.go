package web

// Page view models (docs/PAGES.md). Values reach the browser modules only
// through data-* attributes on <main>. Sizes are bytes, times Unix seconds.

// DashboardView is the view model of "/" for a signed-in user.
type DashboardView struct {
	MaxFileSize   int64    // limits.max_file_size, plaintext bytes (data-max-file-size)
	ExpiryChoices []string // limits.expiry_choices, shortest first
	DefaultExpiry string   // limits.default_expiry (data-default-expiry)
	// MaxDownloads caps the download limit of a share (0: no cap);
	// DefaultMaxDownloads prefills it (0: empty).
	MaxDownloads        int64
	DefaultMaxDownloads int64
	MaxRequestFiles     int // limits.max_request_files
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

// DownloadCap is the largest download limit the form accepts.
func (v *DashboardView) DownloadCap() int64 {
	if v.MaxDownloads > 0 {
		return v.MaxDownloads
	}
	return 999_999
}

// RequestFilesValue is the file count a new request link starts with.
func (v *DashboardView) RequestFilesValue() int {
	return min(10, max(v.MaxRequestFiles, 1))
}

// EmptyDownloads is the download limit a share gets when the field is left
// empty under a cap: the default, else the cap.
func (v *DashboardView) EmptyDownloads() int64 {
	if v.DefaultMaxDownloads > 0 {
		return v.DefaultMaxDownloads
	}
	return v.MaxDownloads
}
