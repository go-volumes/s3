// Copyright (c) 2026, the go-volumes/s3 authors
// SPDX-License-Identifier: BSD-3-Clause

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func init() {
	// Pin the signing clock so request signatures are deterministic in tests.
	nowUTC = func() time.Time { return time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC) }
}

// memStore is a tiny in-memory object store backing the httptest server.
type memStore struct {
	mu   sync.Mutex
	objs map[string][]byte
}

func newMemStore() *memStore { return &memStore{objs: map[string][]byte{}} }

func s3ErrorXML(code, msg string) string {
	return fmt.Sprintf(`<?xml version="1.0"?><Error><Code>%s</Code><Message>%s</Message><Resource>/x</Resource><RequestId>req1</RequestId></Error>`, code, msg)
}

// handler emulates path-style S3: /bucket/key.
func (m *memStore) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Errorf("request not signed: %s %s", r.Method, r.URL.Path)
		}
		// Strip /bucket prefix.
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
		key := ""
		if len(parts) == 2 {
			key = parts[1]
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			data, ok := m.objs[key]
			if !ok {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusNotFound)
				io.WriteString(w, s3ErrorXML("NoSuchKey", "no key"))
				return
			}
			if rg := r.Header.Get("Range"); rg != "" {
				lo, hi := parseRange(rg, len(data))
				w.Header().Set("Content-Length", strconv.Itoa(hi-lo))
				w.WriteHeader(http.StatusPartialContent)
				w.Write(data[lo:hi])
				return
			}
			w.Write(data)
		case http.MethodHead:
			data, ok := m.objs[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			w.WriteHeader(http.StatusOK)
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			m.objs[key] = body
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			if _, ok := m.objs[key]; !ok {
				w.WriteHeader(http.StatusNotFound)
				io.WriteString(w, s3ErrorXML("NoSuchKey", "no key"))
				return
			}
			delete(m.objs, key)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

func parseRange(rg string, size int) (int, int) {
	rg = strings.TrimPrefix(rg, "bytes=")
	dash := strings.IndexByte(rg, '-')
	lo, _ := strconv.Atoi(rg[:dash])
	hiStr := rg[dash+1:]
	if hiStr == "" {
		return lo, size
	}
	hi, _ := strconv.Atoi(hiStr)
	hi++ // inclusive→exclusive
	if hi > size {
		hi = size
	}
	return lo, hi
}

func newTestClient(t *testing.T, srvURL string) *Client {
	c, err := New(Config{
		Endpoint:  srvURL,
		Region:    "us-east-1",
		Bucket:    "bkt",
		AccessKey: "AKIDEXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		PathStyle: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestPutGetRoundTrip(t *testing.T) {
	m := newMemStore()
	srv := httptest.NewServer(m.handler(t))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	ctx := context.Background()

	if err := c.Put(ctx, "dir/obj", []byte("hello world")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := c.Get(ctx, "dir/obj")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "hello world" {
		t.Errorf("Get = %q", got)
	}
}

func TestPutNilBody(t *testing.T) {
	m := newMemStore()
	srv := httptest.NewServer(m.handler(t))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	if err := c.Put(context.Background(), "empty", nil); err != nil {
		t.Fatalf("Put nil: %v", err)
	}
	got, err := c.Get(context.Background(), "empty")
	if err != nil || len(got) != 0 {
		t.Fatalf("Get empty = %q, %v", got, err)
	}
}

func TestGetRange(t *testing.T) {
	m := newMemStore()
	srv := httptest.NewServer(m.handler(t))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	ctx := context.Background()
	c.Put(ctx, "k", []byte("0123456789"))

	got, err := c.GetRange(ctx, "k", 2, 3)
	if err != nil {
		t.Fatalf("GetRange: %v", err)
	}
	if string(got) != "234" {
		t.Errorf("GetRange = %q, want 234", got)
	}
	// length<=0 → to EOF.
	got, err = c.GetRange(ctx, "k", 7, 0)
	if err != nil {
		t.Fatalf("GetRange EOF: %v", err)
	}
	if string(got) != "789" {
		t.Errorf("GetRange to EOF = %q, want 789", got)
	}
}

func TestHead(t *testing.T) {
	m := newMemStore()
	srv := httptest.NewServer(m.handler(t))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	ctx := context.Background()
	c.Put(ctx, "k", []byte("12345"))

	size, exists, err := c.Head(ctx, "k")
	if err != nil || !exists || size != 5 {
		t.Fatalf("Head = %d, %v, %v", size, exists, err)
	}
	_, exists, err = c.Head(ctx, "missing")
	if err != nil || exists {
		t.Fatalf("Head missing = exists %v, err %v", exists, err)
	}
}

func TestGetNotFound(t *testing.T) {
	m := newMemStore()
	srv := httptest.NewServer(m.handler(t))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	_, err := c.Get(context.Background(), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing err = %v, want ErrNotFound", err)
	}
}

func TestDeleteIdempotent(t *testing.T) {
	m := newMemStore()
	srv := httptest.NewServer(m.handler(t))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	ctx := context.Background()
	c.Put(ctx, "k", []byte("x"))
	if err := c.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Deleting again (404) is not an error.
	if err := c.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete missing: %v", err)
	}
}

func TestContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte("late"))
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Get(ctx, "k")
	if err == nil {
		t.Fatal("expected context cancel error")
	}
}

// failDoer returns a transport error for every request.
type failDoer struct{}

func (failDoer) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("boom")
}

func TestTransportError(t *testing.T) {
	c, _ := New(Config{
		Endpoint: "https://s3.example.com", Region: "us-east-1", Bucket: "b",
		AccessKey: "a", SecretKey: "s", PathStyle: true, HTTPClient: failDoer{},
	})
	if _, err := c.Get(context.Background(), "k"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected transport error, got %v", err)
	}
	if err := c.Put(context.Background(), "k", []byte("x")); err == nil {
		t.Fatal("expected Put transport error")
	}
	if err := c.Delete(context.Background(), "k"); err == nil {
		t.Fatal("expected Delete transport error")
	}
	if _, _, err := c.Head(context.Background(), "k"); err == nil {
		t.Fatal("expected Head transport error")
	}
}

// codeDoer returns a fixed status and body.
type codeDoer struct {
	code int
	body string
	ctyp string
}

func (d codeDoer) Do(r *http.Request) (*http.Response, error) {
	h := http.Header{}
	if d.ctyp != "" {
		h.Set("Content-Type", d.ctyp)
	}
	return &http.Response{
		StatusCode: d.code,
		Body:       io.NopCloser(strings.NewReader(d.body)),
		Header:     h,
	}, nil
}

func TestS3ErrorParsed(t *testing.T) {
	c, _ := New(Config{
		Endpoint: "https://s3.example.com", Region: "us-east-1", Bucket: "b",
		AccessKey: "a", SecretKey: "s", PathStyle: true,
		HTTPClient: codeDoer{code: 403, body: s3ErrorXML("AccessDenied", "denied")},
	})
	_, err := c.Get(context.Background(), "k")
	var se *Error
	if !errors.As(err, &se) {
		t.Fatalf("expected *Error, got %v", err)
	}
	if se.Code != "AccessDenied" || se.StatusCode != 403 {
		t.Errorf("Error = %+v", se)
	}
	if !strings.Contains(se.Error(), "AccessDenied") {
		t.Errorf("Error() = %q", se.Error())
	}
}

func TestNoSuchKeyMapsNotFound(t *testing.T) {
	// A 200-status-less response with NoSuchKey code and non-404 status still
	// maps to ErrNotFound via Error.Is.
	c, _ := New(Config{
		Endpoint: "https://s3.example.com", Region: "us-east-1", Bucket: "b",
		AccessKey: "a", SecretKey: "s", PathStyle: true,
		HTTPClient: codeDoer{code: 400, body: s3ErrorXML("NoSuchKey", "missing")},
	})
	_, err := c.Get(context.Background(), "k")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("NoSuchKey should map to ErrNotFound, got %v", err)
	}
}

func TestMalformedXMLError(t *testing.T) {
	c, _ := New(Config{
		Endpoint: "https://s3.example.com", Region: "us-east-1", Bucket: "b",
		AccessKey: "a", SecretKey: "s", PathStyle: true,
		HTTPClient: codeDoer{code: 500, body: "<<<not xml>>>"},
	})
	_, err := c.Get(context.Background(), "k")
	var se *Error
	if !errors.As(err, &se) {
		t.Fatalf("expected *Error, got %v", err)
	}
	if se.Code != "Unknown" || se.StatusCode != 500 {
		t.Errorf("malformed xml Error = %+v", se)
	}
}

func TestEmptyBodyError(t *testing.T) {
	c, _ := New(Config{
		Endpoint: "https://s3.example.com", Region: "us-east-1", Bucket: "b",
		AccessKey: "a", SecretKey: "s", PathStyle: true,
		HTTPClient: codeDoer{code: 503, body: ""},
	})
	_, err := c.Get(context.Background(), "k")
	var se *Error
	if !errors.As(err, &se) || se.Code != "Unknown" {
		t.Fatalf("empty-body error = %v", err)
	}
}

func TestHeadBadContentLength(t *testing.T) {
	c, _ := New(Config{
		Endpoint: "https://s3.example.com", Region: "us-east-1", Bucket: "b",
		AccessKey: "a", SecretKey: "s", PathStyle: true,
		HTTPClient: codeDoer{code: 200, body: "", ctyp: "x"},
	})
	// Manually craft a doer returning a bad Content-Length header.
	c.doer = clDoer{}
	_, _, err := c.Head(context.Background(), "k")
	if err == nil || !strings.Contains(err.Error(), "Content-Length") {
		t.Fatalf("expected bad Content-Length error, got %v", err)
	}
}

type clDoer struct{}

func (clDoer) Do(*http.Request) (*http.Response, error) {
	h := http.Header{}
	h.Set("Content-Length", "not-a-number")
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: h}, nil
}

func TestHeadNoContentLength(t *testing.T) {
	c, _ := New(Config{
		Endpoint: "https://s3.example.com", Region: "us-east-1", Bucket: "b",
		AccessKey: "a", SecretKey: "s", PathStyle: true,
		HTTPClient: nclDoer{},
	})
	size, exists, err := c.Head(context.Background(), "k")
	if err != nil || !exists || size != 0 {
		t.Fatalf("Head no CL = %d, %v, %v", size, exists, err)
	}
}

type nclDoer struct{}

func (nclDoer) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
}

// recordDoer captures the outgoing request (its Host, URL, range header) and
// returns a fixed 200 so virtual-host addressing can be asserted without a real
// DNS lookup for bucket.host.
type recordDoer struct {
	req *http.Request
}

func (d *recordDoer) Do(r *http.Request) (*http.Response, error) {
	d.req = r
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: http.Header{}}, nil
}

func TestVirtualHostAddressing(t *testing.T) {
	rec := &recordDoer{}
	c, _ := New(Config{
		Endpoint: "https://s3.us-east-1.amazonaws.com", Region: "us-east-1", Bucket: "mybkt",
		AccessKey: "a", SecretKey: "s", PathStyle: false, HTTPClient: rec,
	})
	if _, err := c.Get(context.Background(), "the/key"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.req.Host != "mybkt.s3.us-east-1.amazonaws.com" {
		t.Errorf("virtual-host Host = %q", rec.req.Host)
	}
	if rec.req.URL.Path != "/the/key" {
		t.Errorf("virtual-host path = %q", rec.req.URL.Path)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{Bucket: "b"}); err == nil {
		t.Error("expected empty-endpoint error")
	}
	if _, err := New(Config{Endpoint: "https://x"}); err == nil {
		t.Error("expected empty-bucket error")
	}
	if _, err := New(Config{Endpoint: "://bad", Bucket: "b"}); err == nil {
		t.Error("expected parse error")
	}
	if _, err := New(Config{Endpoint: "no-scheme-no-host", Bucket: "b"}); err == nil {
		t.Error("expected no-host error")
	}
}

func TestBuildRequestError(t *testing.T) {
	c, _ := New(Config{
		Endpoint: "https://s3.example.com", Region: "us-east-1", Bucket: "b",
		AccessKey: "a", SecretKey: "s", PathStyle: true, HTTPClient: failDoer{},
	})
	// An invalid method makes http.NewRequestWithContext fail.
	if _, err := c.do(context.Background(), "BAD METHOD", "k", nil, ""); err == nil ||
		!strings.Contains(err.Error(), "build request") {
		t.Fatalf("expected build-request error, got %v", err)
	}
}

func TestErrorIsNonNotFound(t *testing.T) {
	e := &Error{StatusCode: 500, Code: "InternalError"}
	if errors.Is(e, ErrNotFound) {
		t.Error("500 InternalError should not be ErrNotFound")
	}
	if e.Is(errors.New("other")) {
		t.Error("Is(other) should be false")
	}
}

func TestParseS3ErrorEdgeCases(t *testing.T) {
	if parseS3Error(nil) != nil {
		t.Error("nil body should parse to nil")
	}
	if parseS3Error([]byte("")) != nil {
		t.Error("empty body should parse to nil")
	}
	// Valid XML but no <Code> → nil.
	if parseS3Error([]byte(`<Error><Message>m</Message></Error>`)) != nil {
		t.Error("error without code should parse to nil")
	}
}

func TestGetRangeToEndDoer(t *testing.T) {
	rec := &recordDoer{}
	c, _ := New(Config{
		Endpoint: "https://s3.example.com", Region: "us-east-1", Bucket: "b",
		AccessKey: "a", SecretKey: "s", PathStyle: true, HTTPClient: rec,
	})
	if _, err := c.GetRange(context.Background(), "k", 5, 0); err != nil {
		t.Fatalf("GetRange: %v", err)
	}
	if rec.req.Header.Get("Range") != "bytes=5-" {
		t.Errorf("range header = %q, want bytes=5-", rec.req.Header.Get("Range"))
	}
}

func TestGetRangeError(t *testing.T) {
	c, _ := New(Config{
		Endpoint: "https://s3.example.com", Region: "us-east-1", Bucket: "b",
		AccessKey: "a", SecretKey: "s", PathStyle: true, HTTPClient: failDoer{},
	})
	if _, err := c.GetRange(context.Background(), "k", 0, 10); err == nil {
		t.Fatal("expected GetRange transport error")
	}
}

func TestEncodedKeyPath(t *testing.T) {
	var gotRawPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawPath = r.URL.EscapedPath()
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	if _, err := c.Get(context.Background(), "a b/c+d"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !strings.Contains(gotRawPath, "a%20b") || !strings.Contains(gotRawPath, "c%2Bd") {
		t.Errorf("escaped path = %q", gotRawPath)
	}
}
