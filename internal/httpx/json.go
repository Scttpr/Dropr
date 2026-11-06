package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
)

// APIError is the JSON error body of every API (ARCHITECTURE.md §3): a
// stable machine code and a plain-language message safe to show users.
type APIError struct {
	Status  int    `json:"-"`
	Code    string `json:"error"`
	Message string `json:"message"`
}

func (e *APIError) Error() string { return e.Code + ": " + e.Message }

// Errorf returns an APIError.
func Errorf(status int, code, format string, a ...any) *APIError {
	return &APIError{Status: status, Code: code, Message: fmt.Sprintf(format, a...)}
}

// WriteJSON writes v as a JSON response with status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// WriteError writes an APIError.
func WriteError(w http.ResponseWriter, e *APIError) {
	WriteJSON(w, e.Status, e)
}

// ErrBadJSON is wrapped by DecodeJSON for every rejected body.
var ErrBadJSON = errors.New("httpx: bad JSON body")

// DecodeJSON strictly decodes a JSON request body into v: the content type
// must be application/json, the body exactly one JSON value with no unknown
// fields and no trailing data. Body size is bounded by LimitBody.
func DecodeJSON(r *http.Request, v any) error {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		return fmt.Errorf("%w: content type must be application/json", ErrBadJSON)
	}
	return DecodeJSONBytesFrom(r.Body, v)
}

// DecodeJSONBytesFrom is the content-type-independent part of DecodeJSON.
func DecodeJSONBytesFrom(body io.Reader, v any) error {
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %w", ErrBadJSON, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing data", ErrBadJSON)
	}
	return nil
}
