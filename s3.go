// Copyright (c) 2026, the go-volumes/s3 authors
// SPDX-License-Identifier: BSD-3-Clause

// Package s3 implements an S3-backed block store: a flat byte address space
// mapped onto fixed-size chunk objects in an S3 bucket, with an in-memory
// write-back cache. The *Store type satisfies the go-volumes/pool Backing
// interface (io.ReaderAt, io.WriterAt, Truncate, Sync, io.Closer), so a
// copy-on-write volume pool — or any block consumer — can run on S3 with no
// local file.
//
// Production code here keeps no dependency on go-volumes/pool; the Backing
// conformance is asserted only in the test file s3_conformance_test.go.
//
// Layout in the bucket (all under a configurable key prefix):
//
//	<prefix>/__meta              little metadata object: logical size + chunk size
//	<prefix>/<016d chunk index>  one object per 4 MiB (default) data chunk
//
// A chunk that was never written reads back as zeros (the store is sparse): the
// logical size in the metadata object — not the presence of chunk objects —
// defines the address space. Writes are buffered in the cache and flushed to S3
// only on Sync (or Close), which is the durability point.
package s3

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/go-volumes/s3/client"
)

// DefaultChunkSize is the default chunk-object size (4 MiB).
const DefaultChunkSize = 4 << 20

// metaKey is the object name (under the prefix) holding the store metadata.
const metaKey = "__meta"

// objectStore is the subset of the S3 client the Store needs; tests inject a
// fake to drive error paths.
type objectStore interface {
	GetRange(ctx context.Context, key string, off, length int64) ([]byte, error)
	Get(ctx context.Context, key string) ([]byte, error)
	Put(ctx context.Context, key string, body []byte) error
	Delete(ctx context.Context, key string) error
	Head(ctx context.Context, key string) (size int64, exists bool, err error)
}

// meta is the persisted store metadata (JSON, stdlib-encoded).
type meta struct {
	Size      int64 `json:"size"`       // logical byte size of the address space
	ChunkSize int64 `json:"chunk_size"` // chunk-object size in bytes
}

// chunk is one cached chunk's data and dirty state.
type chunk struct {
	data  []byte // exactly ChunkSize bytes
	dirty bool
}

// Store is an S3-backed block store satisfying the pool.Backing shape.
type Store struct {
	mu        sync.Mutex
	cli       objectStore
	prefix    string
	chunkSize int64
	size      int64
	cache     map[int64]*chunk
	ctx       context.Context
	closed    bool
}

// Config configures Open.
type Config struct {
	// Client is the S3 client (or any objectStore). Required.
	Client objectStore
	// Prefix is the key prefix under which chunk objects and metadata live.
	Prefix string
	// ChunkSize is the chunk-object size in bytes; must be a power of two >= 512.
	// Zero means DefaultChunkSize.
	ChunkSize int64
	// Context is used for all S3 operations. Zero means context.Background().
	Context context.Context
}

// Open opens (or, if no metadata object exists, initialises) a Store. If the
// metadata object is present its logical size and chunk size are adopted and
// the supplied ChunkSize, when non-zero, must match. Otherwise the store starts
// empty at size 0 with the requested (or default) chunk size.
func Open(cfg Config) (*Store, error) {
	if cfg.Client == nil {
		return nil, errors.New("s3: nil client")
	}
	cs := cfg.ChunkSize
	if cs == 0 {
		cs = DefaultChunkSize
	}
	if cs < 512 || cs&(cs-1) != 0 {
		return nil, fmt.Errorf("s3: chunk size %d must be a power of two >= 512", cs)
	}
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}
	s := &Store{
		cli:       cfg.Client,
		prefix:    cfg.Prefix,
		chunkSize: cs,
		cache:     map[int64]*chunk{},
		ctx:       ctx,
	}
	blob, err := s.cli.Get(ctx, s.key(metaKey))
	switch {
	case err == nil:
		var m meta
		if jerr := json.Unmarshal(blob, &m); jerr != nil {
			return nil, fmt.Errorf("s3: decode metadata: %w", jerr)
		}
		if cfg.ChunkSize != 0 && m.ChunkSize != cfg.ChunkSize {
			return nil, fmt.Errorf("s3: chunk size mismatch: store has %d, requested %d", m.ChunkSize, cfg.ChunkSize)
		}
		s.chunkSize = m.ChunkSize
		s.size = m.Size
	case errors.Is(err, client.ErrNotFound):
		// Fresh store: nothing persisted yet.
	default:
		return nil, fmt.Errorf("s3: read metadata: %w", err)
	}
	return s, nil
}

// key joins the prefix and a relative name.
func (s *Store) key(name string) string {
	if s.prefix == "" {
		return name
	}
	return s.prefix + "/" + name
}

// chunkKey returns the object key for chunk index i (zero-padded for ordering).
func (s *Store) chunkKey(i int64) string {
	return s.key(fmt.Sprintf("%016d", i))
}

// ChunkSize returns the store's chunk size in bytes.
func (s *Store) ChunkSize() int64 { return s.chunkSize }

// Size returns the current logical size in bytes.
func (s *Store) Size() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.size
}

// getChunk returns chunk i from the cache, fetching it from S3 (or zero-filling
// a never-written chunk) on a miss. Caller holds s.mu.
func (s *Store) getChunk(i int64) (*chunk, error) {
	if c, ok := s.cache[i]; ok {
		return c, nil
	}
	buf := make([]byte, s.chunkSize)
	data, err := s.cli.Get(s.ctx, s.chunkKey(i))
	switch {
	case err == nil:
		copy(buf, data) // short objects (last chunk) zero-pad on the right
	case errors.Is(err, client.ErrNotFound):
		// Sparse: never written → zeros.
	default:
		return nil, err
	}
	c := &chunk{data: buf}
	s.cache[i] = c
	return c, nil
}

// ReadAt implements io.ReaderAt. Reads past the logical size return io.EOF with
// the bytes read so far, matching os.File semantics.
func (s *Store) ReadAt(p []byte, off int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, errClosed
	}
	if off < 0 {
		return 0, errors.New("s3: negative offset")
	}
	n := 0
	for n < len(p) {
		pos := off + int64(n)
		if pos >= s.size {
			return n, io.EOF
		}
		ci := pos / s.chunkSize
		within := pos % s.chunkSize
		cnt := int(s.chunkSize - within)
		if cnt > len(p)-n {
			cnt = len(p) - n
		}
		// Do not read past the logical size.
		if pos+int64(cnt) > s.size {
			cnt = int(s.size - pos)
		}
		c, err := s.getChunk(ci)
		if err != nil {
			return n, err
		}
		copy(p[n:n+cnt], c.data[within:within+int64(cnt)])
		n += cnt
	}
	return n, nil
}

// WriteAt implements io.WriterAt with read-modify-write of the touched chunks.
// Written bytes beyond the current logical size grow the size. Writes only
// mutate the cache; durability happens at Sync.
func (s *Store) WriteAt(p []byte, off int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, errClosed
	}
	if off < 0 {
		return 0, errors.New("s3: negative offset")
	}
	n := 0
	for n < len(p) {
		pos := off + int64(n)
		ci := pos / s.chunkSize
		within := pos % s.chunkSize
		cnt := int(s.chunkSize - within)
		if cnt > len(p)-n {
			cnt = len(p) - n
		}
		c, err := s.getChunk(ci)
		if err != nil {
			return n, err
		}
		copy(c.data[within:within+int64(cnt)], p[n:n+cnt])
		c.dirty = true
		n += cnt
	}
	if off+int64(n) > s.size {
		s.size = off + int64(n)
	}
	return n, nil
}

// Truncate sets the logical size. Growing is sparse (no objects written until a
// later WriteAt+Sync). Shrinking drops cached chunks and deletes S3 chunk
// objects that lie entirely beyond the new size; a partially-truncated final
// chunk has its tail zeroed and is marked dirty.
func (s *Store) Truncate(size int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errClosed
	}
	if size < 0 {
		return errors.New("s3: negative size")
	}
	old := s.size
	s.size = size
	if size >= old {
		return nil // grow: nothing to discard
	}
	// Shrink. The first chunk index fully beyond the new size:
	firstGone := (size + s.chunkSize - 1) / s.chunkSize
	lastOld := (old - 1) / s.chunkSize
	for i := firstGone; i <= lastOld; i++ {
		delete(s.cache, i)
		if err := s.cli.Delete(s.ctx, s.chunkKey(i)); err != nil {
			return err
		}
	}
	// Zero the tail of the partially-kept final chunk, if any.
	if within := size % s.chunkSize; within != 0 {
		ci := size / s.chunkSize
		c, err := s.getChunk(ci)
		if err != nil {
			return err
		}
		for j := within; j < s.chunkSize; j++ {
			c.data[j] = 0
		}
		c.dirty = true
	}
	return nil
}

// Sync flushes every dirty chunk and then the metadata object to S3, clearing
// dirty flags. This is the store's durability point.
func (s *Store) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sync()
}

func (s *Store) sync() error {
	if s.closed {
		return errClosed
	}
	for i, c := range s.cache {
		if !c.dirty {
			continue
		}
		if err := s.cli.Put(s.ctx, s.chunkKey(i), c.data); err != nil {
			return err
		}
		c.dirty = false
	}
	// json.Marshal of a struct of int64 fields cannot fail, so the error is
	// dropped deliberately rather than left as an unreachable branch.
	blob, _ := json.Marshal(meta{Size: s.size, ChunkSize: s.chunkSize})
	return s.cli.Put(s.ctx, s.key(metaKey), blob)
}

// Close syncs and releases the store. Subsequent operations return an error.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	err := s.sync()
	s.closed = true
	s.cache = nil
	return err
}

var errClosed = errors.New("s3: store closed")
