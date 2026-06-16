# go-volumes/s3

A pure-Go (`CGO_ENABLED=0`), from-scratch **S3-backed block store** that
satisfies the [`go-volumes/pool`](https://github.com/go-volumes/pool)
`Backing` interface. It maps a flat byte address space onto fixed-size chunk
objects in any S3-compatible bucket, with an in-memory write-back cache, so a
copy-on-write volume pool — or any block consumer — can run on object storage
with no local file.

**No external dependencies: the Go standard library only.** No `aws-sdk-go`,
no `minio-go`. AWS Signature Version 4 is implemented from scratch on
`crypto/hmac` + `crypto/sha256`.

## Packages

| Package | Purpose |
| --- | --- |
| `sigv4` | AWS Signature Version 4 request signer (canonical request → string-to-sign → kDate→kRegion→kService→kSigning chain → `Authorization`). Validated byte-for-byte against the official AWS *Signature Version 4 Test Suite*. |
| `client` | Minimal S3 client over `net/http`: `Get` / `GetRange` / `Put` / `Delete` / `Head`, path-style + virtual-host addressing, XML error parsing, `404 → ErrNotFound`, injectable HTTP doer, context cancellation. |
| `s3` (root) | `Store` implementing `pool.Backing` (`ReadAt`, `WriteAt`, `Truncate`, `Sync`, `Close`) over fixed-size chunk objects + a write-back cache + a persisted metadata object. |

## Design

```
bucket layout (all under a configurable prefix):

  <prefix>/__meta              metadata: { logical size, chunk size }
  <prefix>/0000000000000000    chunk 0   (default 4 MiB)
  <prefix>/0000000000000001    chunk 1
  ...
```

- **Chunked address space.** The logical size lives in `__meta`, not in the
  set of present objects, so the store is **sparse**: a chunk that was never
  written reads back as zeros.
- **Write-back cache.** `WriteAt` does read-modify-write of the touched chunks
  in memory and marks them dirty; nothing hits S3 until `Sync`. `Sync` `Put`s
  every dirty chunk then the metadata object — this is the durability point.
- **`Truncate`.** Grows sparsely; on shrink it deletes chunk objects fully
  beyond the new size and zeroes the tail of the partially-kept final chunk.
- **Reopen.** `Open` reads `__meta` if present and adopts its size and chunk
  size, so a reopened store knows its geometry.
- **Concurrency-safe** via a mutex (the pool already calls under its own lock;
  the store is defensive anyway).

## Example

```go
cli, _ := client.New(client.Config{
    Endpoint: "https://s3.us-east-1.amazonaws.com",
    Region:   "us-east-1",
    Bucket:   "my-bucket",
    AccessKey: os.Getenv("AWS_ACCESS_KEY_ID"),
    SecretKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
})
store, _ := s3.Open(s3.Config{Client: cli, Prefix: "vol1"})

// Run a copy-on-write pool directly on S3:
p, _ := pool.CreateWith(store, 8<<20, 4096)
vol, _ := p.CreateVolume("data", 1<<20)
vol.WriteAt([]byte("hello"), 0)
p.Close() // Sync + Close — durably committed to S3
```

For MinIO / garage set `PathStyle: true`.

## Tests

`CGO_ENABLED=0`, 100% statement coverage, gated in CI:

- `sigv4`: the official AWS test-suite vectors (`get-vanilla`,
  `get-vanilla-query-order-key-case`, `get-header-value-trim`,
  `post-x-www-form-urlencoded`, `get-utf8`) asserted byte-for-byte on the
  canonical request, string-to-sign, and `Authorization`; the get-vanilla
  signature and signing key pinned to AWS's published golden values.
- `client`: driven against an `httptest.Server` emulating GET / ranged-GET /
  PUT / DELETE / HEAD plus S3-style XML errors; ctx-cancel, non-2xx,
  `404 → ErrNotFound`, malformed XML.
- `Store`: the real consumer — `pool.CreateWith` + volume write/read round-trip,
  cross-chunk and partial-chunk read-modify-write, sparse zero reads, EOF past
  size, `Truncate` up/down with chunk GC, `Sync` flushes dirty + meta,
  reopen-reads-meta, and client error propagation.

CI runs `native` (amd64 + arm64) and `emulated` (riscv64, loong64, ppc64le,
**s390x** — the big-endian check for SigV4 byte handling) under QEMU.

## License

BSD-3-Clause. See [LICENSE](LICENSE).
