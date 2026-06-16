// Copyright (c) 2026, the go-volumes/s3 authors
// SPDX-License-Identifier: BSD-3-Clause

package s3_test

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

	s3 "github.com/go-volumes/s3"
	"github.com/go-volumes/s3/client"
)

// httpTestStore is an in-memory S3 emulator fronted by an httptest.Server, used
// to build a real client.Client and exercise the Store end-to-end over HTTP.
type httpTestStore struct {
	srv  *httptest.Server
	mu   sync.Mutex
	objs map[string][]byte
}

func newHTTPTestStore(t *testing.T) *httpTestStore {
	t.Helper()
	h := &httpTestStore{objs: map[string][]byte{}}
	h.srv = httptest.NewServer(http.HandlerFunc(h.serve))
	return h
}

func (h *httpTestStore) Close() { h.srv.Close() }

func (h *httpTestStore) serve(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	key := ""
	if len(parts) == 2 {
		key = parts[1]
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		data, ok := h.objs[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `<Error><Code>NoSuchKey</Code><Message>nope</Message></Error>`)
			return
		}
		if rg := r.Header.Get("Range"); rg != "" {
			lo, hi := parseRange(rg, len(data))
			w.WriteHeader(http.StatusPartialContent)
			w.Write(data[lo:hi])
			return
		}
		w.Write(data)
	case http.MethodHead:
		data, ok := h.objs[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		h.objs[key] = body
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		delete(h.objs, key)
		w.WriteHeader(http.StatusNoContent)
	}
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
	hi++
	if hi > size {
		hi = size
	}
	return lo, hi
}

func (h *httpTestStore) openStore(t *testing.T, prefix string, chunkSize int64) *s3.Store {
	t.Helper()
	cli, err := client.New(client.Config{
		Endpoint: h.srv.URL, Region: "us-east-1", Bucket: "bkt",
		AccessKey: "AKIDEXAMPLE", SecretKey: "secret", PathStyle: true,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	st, err := s3.Open(s3.Config{Client: cli, Prefix: prefix, ChunkSize: chunkSize})
	if err != nil {
		t.Fatalf("s3.Open: %v", err)
	}
	return st
}

// ---- direct Store tests over the HTTP emulator ----

func newStore(t *testing.T, chunkSize int64) (*httpTestStore, *s3.Store) {
	srv := newHTTPTestStore(t)
	t.Cleanup(srv.Close)
	return srv, srv.openStore(t, "vol", chunkSize)
}

func TestWriteReadSingleChunk(t *testing.T) {
	_, st := newStore(t, 512)
	if n, err := st.WriteAt([]byte("hello"), 0); err != nil || n != 5 {
		t.Fatalf("WriteAt: %d %v", n, err)
	}
	buf := make([]byte, 5)
	if n, err := st.ReadAt(buf, 0); err != nil || n != 5 {
		t.Fatalf("ReadAt: %d %v", n, err)
	}
	if string(buf) != "hello" {
		t.Errorf("read = %q", buf)
	}
}

func TestCrossChunkWriteRead(t *testing.T) {
	_, st := newStore(t, 512)
	data := make([]byte, 1500) // spans 3 chunks
	for i := range data {
		data[i] = byte(i)
	}
	if _, err := st.WriteAt(data, 100); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := st.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	got := make([]byte, 1500)
	if _, err := st.ReadAt(got, 100); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	for i := range data {
		if got[i] != data[i] {
			t.Fatalf("byte %d: got %d want %d", i, got[i], data[i])
		}
	}
}

func TestReadModifyWritePartialChunk(t *testing.T) {
	srv, st := newStore(t, 512)
	full := make([]byte, 512)
	for i := range full {
		full[i] = 0xAA
	}
	st.WriteAt(full, 0)
	st.Sync()
	// Reopen a fresh store (cold cache) and overwrite only the middle bytes:
	// this forces a fetch-modify-write of an existing chunk.
	st2 := srv.openStore(t, "vol", 512)
	if _, err := st2.WriteAt([]byte{1, 2, 3}, 200); err != nil {
		t.Fatalf("partial WriteAt: %v", err)
	}
	got := make([]byte, 512)
	if _, err := st2.ReadAt(got, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if got[199] != 0xAA || got[200] != 1 || got[201] != 2 || got[202] != 3 || got[203] != 0xAA {
		t.Errorf("read-modify-write wrong: %v", got[199:204])
	}
}

func TestSparseZeroRead(t *testing.T) {
	_, st := newStore(t, 512)
	// Grow to 2000 bytes without writing chunk 1 or 2.
	if err := st.Truncate(2000); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	st.WriteAt([]byte{9}, 0)
	got := make([]byte, 600)
	if _, err := st.ReadAt(got, 700); err != nil { // entirely in never-written region
		t.Fatalf("ReadAt sparse: %v", err)
	}
	for i, b := range got {
		if b != 0 {
			t.Fatalf("sparse byte %d = %d, want 0", i, b)
		}
	}
}

func TestEOFPastSize(t *testing.T) {
	_, st := newStore(t, 512)
	st.WriteAt([]byte("abc"), 0) // size = 3
	buf := make([]byte, 10)
	n, err := st.ReadAt(buf, 0)
	if n != 3 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt past end = %d, %v, want 3, EOF", n, err)
	}
	// Read starting exactly at size → 0, EOF.
	n, err = st.ReadAt(buf, 3)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt at size = %d, %v", n, err)
	}
}

func TestReadStraddlesSize(t *testing.T) {
	_, st := newStore(t, 512)
	st.WriteAt(make([]byte, 600), 0) // size 600, spans 2 chunks
	buf := make([]byte, 100)
	// Read [550,650): bytes 550..599 valid, then EOF.
	n, err := st.ReadAt(buf, 550)
	if n != 50 || !errors.Is(err, io.EOF) {
		t.Fatalf("straddle read = %d, %v, want 50, EOF", n, err)
	}
}

func TestTruncateGrowSparse(t *testing.T) {
	srv, st := newStore(t, 512)
	st.WriteAt([]byte("x"), 0)
	if err := st.Truncate(5000); err != nil {
		t.Fatalf("Truncate grow: %v", err)
	}
	if st.Size() != 5000 {
		t.Errorf("Size = %d, want 5000", st.Size())
	}
	st.Sync()
	// No data chunks beyond chunk 0 were written.
	srv.mu.Lock()
	count := 0
	for k := range srv.objs {
		if !strings.HasSuffix(k, "__meta") {
			count++
		}
	}
	srv.mu.Unlock()
	if count != 1 {
		t.Errorf("expected 1 data chunk after sparse grow, got %d", count)
	}
}

func TestTruncateShrinkGC(t *testing.T) {
	srv, st := newStore(t, 512)
	// Write 4 chunks worth.
	st.WriteAt(make([]byte, 2048), 0)
	st.Sync()
	srv.mu.Lock()
	before := len(srv.objs)
	srv.mu.Unlock()
	// Shrink to 600 bytes → keep chunks 0,1; delete 2,3.
	if err := st.Truncate(600); err != nil {
		t.Fatalf("Truncate shrink: %v", err)
	}
	srv.mu.Lock()
	after := len(srv.objs)
	srv.mu.Unlock()
	if after >= before {
		t.Errorf("expected chunk GC: before=%d after=%d", before, after)
	}
	// The kept partial chunk's tail must read as zeros.
	st.Truncate(2048) // grow back
	got := make([]byte, 512)
	st.ReadAt(got, 512) // chunk 1, bytes 512..1023; 600..1023 were zeroed
	for i := 600 - 512; i < 512; i++ {
		if got[i] != 0 {
			t.Fatalf("tail not zeroed at chunk-byte %d: %d", i, got[i])
		}
	}
}

func TestTruncateShrinkAligned(t *testing.T) {
	// Shrink to an exact chunk boundary: no partial-tail zeroing path.
	_, st := newStore(t, 512)
	st.WriteAt(make([]byte, 1024), 0)
	if err := st.Truncate(512); err != nil {
		t.Fatalf("Truncate aligned: %v", err)
	}
	if st.Size() != 512 {
		t.Errorf("Size = %d", st.Size())
	}
}

func TestReopenReadsMeta(t *testing.T) {
	srv, st := newStore(t, 512)
	st.WriteAt([]byte("persisted"), 100)
	st.Truncate(4096)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st2 := srv.openStore(t, "vol", 0) // adopt persisted chunk size
	if st2.Size() != 4096 {
		t.Errorf("reopened Size = %d, want 4096", st2.Size())
	}
	if st2.ChunkSize() != 512 {
		t.Errorf("reopened ChunkSize = %d, want 512", st2.ChunkSize())
	}
	got := make([]byte, 9)
	st2.ReadAt(got, 100)
	if string(got) != "persisted" {
		t.Errorf("reopened read = %q", got)
	}
}

func TestSyncFlushesDirtyAndMeta(t *testing.T) {
	srv, st := newStore(t, 512)
	st.WriteAt([]byte("data"), 0)
	// Before Sync, nothing is in S3 except possibly nothing.
	srv.mu.Lock()
	pre := len(srv.objs)
	srv.mu.Unlock()
	if pre != 0 {
		t.Fatalf("expected no objects before Sync, got %d", pre)
	}
	if err := st.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	srv.mu.Lock()
	_, hasMeta := srv.objs["vol/__meta"]
	srv.mu.Unlock()
	if !hasMeta {
		t.Error("Sync did not write metadata")
	}
	// A second Sync with no new writes still succeeds (dirty flags cleared).
	if err := st.Sync(); err != nil {
		t.Fatalf("second Sync: %v", err)
	}
}

func TestCloseIdempotent(t *testing.T) {
	_, st := newStore(t, 512)
	st.WriteAt([]byte("x"), 0)
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// Operations after close fail.
	if _, err := st.WriteAt([]byte("y"), 0); err == nil {
		t.Error("WriteAt after Close should fail")
	}
	if _, err := st.ReadAt(make([]byte, 1), 0); err == nil {
		t.Error("ReadAt after Close should fail")
	}
	if err := st.Truncate(0); err == nil {
		t.Error("Truncate after Close should fail")
	}
	if err := st.Sync(); err == nil {
		t.Error("Sync after Close should fail")
	}
}

func TestNegativeOffsets(t *testing.T) {
	_, st := newStore(t, 512)
	if _, err := st.ReadAt(make([]byte, 1), -1); err == nil {
		t.Error("ReadAt negative offset should fail")
	}
	if _, err := st.WriteAt([]byte{1}, -1); err == nil {
		t.Error("WriteAt negative offset should fail")
	}
	if err := st.Truncate(-1); err == nil {
		t.Error("Truncate negative size should fail")
	}
}

// ---- error-injection via a fake objectStore ----

type fakeStore struct {
	objs    map[string][]byte
	failGet bool
	failPut bool
	failDel bool
	getErr  error
}

func newFake() *fakeStore { return &fakeStore{objs: map[string][]byte{}} }

func (f *fakeStore) Get(ctx context.Context, key string) ([]byte, error) {
	if f.failGet {
		if f.getErr != nil {
			return nil, f.getErr
		}
		return nil, errors.New("get boom")
	}
	d, ok := f.objs[key]
	if !ok {
		return nil, fmt.Errorf("%w", client.ErrNotFound)
	}
	return d, nil
}
func (f *fakeStore) GetRange(ctx context.Context, key string, off, length int64) ([]byte, error) {
	return f.Get(ctx, key)
}
func (f *fakeStore) Put(ctx context.Context, key string, body []byte) error {
	if f.failPut {
		return errors.New("put boom")
	}
	f.objs[key] = append([]byte(nil), body...)
	return nil
}
func (f *fakeStore) Delete(ctx context.Context, key string) error {
	if f.failDel {
		return errors.New("delete boom")
	}
	delete(f.objs, key)
	return nil
}
func (f *fakeStore) Head(ctx context.Context, key string) (int64, bool, error) {
	d, ok := f.objs[key]
	return int64(len(d)), ok, nil
}

func TestOpenNilClient(t *testing.T) {
	if _, err := s3.Open(s3.Config{}); err == nil {
		t.Error("nil client should error")
	}
}

func TestOpenBadChunkSize(t *testing.T) {
	if _, err := s3.Open(s3.Config{Client: newFake(), ChunkSize: 100}); err == nil {
		t.Error("non-power-of-two chunk size should error")
	}
	if _, err := s3.Open(s3.Config{Client: newFake(), ChunkSize: 256}); err == nil {
		t.Error("chunk size < 512 should error")
	}
}

func TestOpenMetaReadError(t *testing.T) {
	f := newFake()
	f.failGet = true
	if _, err := s3.Open(s3.Config{Client: f}); err == nil {
		t.Error("meta read error should propagate")
	}
}

func TestOpenMetaDecodeError(t *testing.T) {
	f := newFake()
	f.objs["__meta"] = []byte("{not json")
	if _, err := s3.Open(s3.Config{Client: f}); err == nil {
		t.Error("bad meta JSON should error")
	}
}

func TestOpenChunkSizeMismatch(t *testing.T) {
	f := newFake()
	f.objs["__meta"] = []byte(`{"size":10,"chunk_size":1024}`)
	if _, err := s3.Open(s3.Config{Client: f, ChunkSize: 4096}); err == nil {
		t.Error("chunk size mismatch should error")
	}
}

func TestOpenContextDefault(t *testing.T) {
	// Open with no Context exercises the context.Background() default; a fresh
	// fake has no __meta so it takes the NotFound path.
	st, err := s3.Open(s3.Config{Client: newFake(), Prefix: ""})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if st.Size() != 0 {
		t.Errorf("fresh size = %d", st.Size())
	}
}

func TestGetChunkError(t *testing.T) {
	f := newFake()
	st, _ := s3.Open(s3.Config{Client: f, Context: context.Background()})
	st.Truncate(2048) // size so reads are in-range
	f.failGet = true
	if _, err := st.ReadAt(make([]byte, 10), 0); err == nil {
		t.Error("ReadAt should propagate chunk Get error")
	}
	if _, err := st.WriteAt([]byte{1, 2}, 100); err == nil {
		// partial chunk write must fetch the chunk first
		t.Error("WriteAt should propagate chunk Get error")
	}
}

func TestSyncPutError(t *testing.T) {
	f := newFake()
	st, _ := s3.Open(s3.Config{Client: f})
	st.WriteAt([]byte("x"), 0)
	f.failPut = true
	if err := st.Sync(); err == nil {
		t.Error("Sync should propagate Put error")
	}
}

func TestSyncMetaPutError(t *testing.T) {
	f := newFake()
	st, _ := s3.Open(s3.Config{Client: f})
	// No dirty chunks → loop skipped, only the meta Put runs and fails.
	f.failPut = true
	if err := st.Sync(); err == nil {
		t.Error("Sync should propagate meta Put error")
	}
}

func TestTruncateDeleteError(t *testing.T) {
	f := newFake()
	st, _ := s3.Open(s3.Config{Client: f, ChunkSize: 512})
	st.WriteAt(make([]byte, 2048), 0)
	st.Sync()
	f.failDel = true
	if err := st.Truncate(100); err == nil {
		t.Error("Truncate should propagate Delete error")
	}
}

func TestTruncateTailFetchError(t *testing.T) {
	f := newFake()
	st, _ := s3.Open(s3.Config{Client: f, ChunkSize: 512})
	// Two chunks; shrink to 600 keeps chunk 1 partially, which is not cached
	// after we drop it — force a fetch error on the tail-zero path.
	st.WriteAt(make([]byte, 1024), 0)
	st.Sync()
	// Reopen cold so chunk 1 must be fetched during the tail zero.
	st2, _ := s3.Open(s3.Config{Client: f, ChunkSize: 512})
	f.failGet = true
	if err := st2.Truncate(600); err == nil {
		t.Error("Truncate tail-zero should propagate Get error")
	}
}

func TestPrefixKeying(t *testing.T) {
	f := newFake()
	st, _ := s3.Open(s3.Config{Client: f, Prefix: "myvol", ChunkSize: 512})
	st.WriteAt([]byte("hi"), 0)
	st.Sync()
	foundChunk, foundMeta := false, false
	for k := range f.objs {
		if k == "myvol/__meta" {
			foundMeta = true
		}
		if strings.HasPrefix(k, "myvol/0000") {
			foundChunk = true
		}
	}
	if !foundChunk || !foundMeta {
		t.Errorf("prefix keying wrong: chunk=%v meta=%v keys=%v", foundChunk, foundMeta, keysOf(f.objs))
	}
}

func keysOf(m map[string][]byte) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func TestLastChunkZeroPad(t *testing.T) {
	// A persisted last chunk shorter than ChunkSize must zero-pad on read.
	f := newFake()
	st, _ := s3.Open(s3.Config{Client: f, ChunkSize: 512})
	st.WriteAt([]byte("abc"), 0) // size 3, chunk 0 stored as 512 bytes (padded)
	st.Sync()
	// Manually shorten the stored object to 3 bytes to simulate a compacted
	// store, then reopen and read the tail.
	f.objs["0000000000000000"] = []byte("abc")
	f.objs["__meta"] = []byte(`{"size":512,"chunk_size":512}`)
	st2, _ := s3.Open(s3.Config{Client: f, ChunkSize: 512})
	got := make([]byte, 10)
	n, _ := st2.ReadAt(got, 0)
	if n < 4 || got[0] != 'a' || got[3] != 0 {
		t.Errorf("zero-pad read wrong: n=%d got=%v", n, got[:5])
	}
}
