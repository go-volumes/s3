// Copyright (c) 2026, the go-volumes/s3 authors
// SPDX-License-Identifier: BSD-3-Clause

// Package client is a minimal S3 client built on net/http and signed with AWS
// Signature Version 4 (package sigv4). It uses only the Go standard library —
// no aws-sdk-go, no minio-go.
//
// It supports both virtual-host addressing (bucket.endpoint/key) and path-style
// addressing (endpoint/bucket/key) for S3-compatible stores such as MinIO and
// garage. All requests honour the supplied context for cancellation.
package client

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-volumes/s3/sigv4"
)

// ErrNotFound is returned when S3 responds 404 (NoSuchKey / NoSuchBucket / a
// bare 404). Callers use errors.Is(err, ErrNotFound).
var ErrNotFound = errors.New("s3: not found")

// httpDoer is the subset of *http.Client the client needs; tests inject a
// httptest-backed implementation.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Config configures a Client.
type Config struct {
	Endpoint     string // e.g. https://s3.us-east-1.amazonaws.com or http://127.0.0.1:9000
	Region       string // e.g. us-east-1
	Bucket       string // bucket name
	AccessKey    string
	SecretKey    string
	SessionToken string   // optional STS session token
	PathStyle    bool     // true for MinIO/garage; false for AWS virtual-host
	HTTPClient   httpDoer // optional; defaults to http.DefaultClient
}

// Client talks to one S3 bucket.
type Client struct {
	endpoint  *url.URL
	region    string
	bucket    string
	signer    *sigv4.Signer
	doer      httpDoer
	pathStyle bool
}

// New builds a Client from cfg.
func New(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("s3: empty endpoint")
	}
	if cfg.Bucket == "" {
		return nil, errors.New("s3: empty bucket")
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("s3: parse endpoint: %w", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("s3: endpoint %q has no host", cfg.Endpoint)
	}
	doer := cfg.HTTPClient
	if doer == nil {
		doer = http.DefaultClient
	}
	creds := sigv4.Credentials{
		AccessKeyID:     cfg.AccessKey,
		SecretAccessKey: cfg.SecretKey,
		SessionToken:    cfg.SessionToken,
	}
	return &Client{
		endpoint:  u,
		region:    cfg.Region,
		bucket:    cfg.Bucket,
		signer:    sigv4.New(cfg.Region, "s3", creds),
		doer:      doer,
		pathStyle: cfg.PathStyle,
	}, nil
}

// urlFor builds the request URL and Host header for an object key. The URL's
// Path holds the decoded form and RawPath the SigV4-encoded form, so both the
// signer and net/http agree on the wire bytes.
func (c *Client) urlFor(key string) (*url.URL, string) {
	u := *c.endpoint
	encKey := sigv4.EncodePath(key) // leading-slash, per-segment encoded
	if c.pathStyle {
		// endpoint/bucket/key
		u.Path = "/" + c.bucket + "/" + strings.TrimPrefix(key, "/")
		u.RawPath = "/" + sigv4.EncodePath(c.bucket)[1:] + encKey
		return &u, c.endpoint.Host
	}
	// virtual-host: bucket.endpointHost/key
	host := c.bucket + "." + c.endpoint.Host
	u.Host = host
	u.Path = "/" + strings.TrimPrefix(key, "/")
	u.RawPath = encKey
	return &u, host
}

// requestError builds an error from a non-2xx response, draining the body.
func (c *Client) requestError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w (status 404)", ErrNotFound)
	}
	if se := parseS3Error(body); se != nil {
		se.StatusCode = resp.StatusCode
		return se
	}
	return &Error{StatusCode: resp.StatusCode, Code: "Unknown", Message: strings.TrimSpace(string(body))}
}

// do signs and sends a request, returning the response for 2xx or an error.
func (c *Client) do(ctx context.Context, method, key string, body []byte, rangeHdr string) (*http.Response, error) {
	var hdr http.Header
	if rangeHdr != "" {
		hdr = http.Header{"Range": {rangeHdr}}
	}
	return c.doWith(ctx, method, key, "", body, hdr)
}

// doWith is do with a raw query (a bucket sub-resource such as "object-lock")
// and extra headers, which are signed with the rest.
func (c *Client) doWith(ctx context.Context, method, key, query string, body []byte, hdr http.Header) (*http.Response, error) {
	u, host := c.urlFor(key)
	if key == "" && c.pathStyle {
		// A bucket-level request: endpoint/bucket, no trailing slash.
		u.Path = "/" + c.bucket
		u.RawPath = sigv4.EncodePath(c.bucket)
	}
	u.RawQuery = query
	var rdr io.Reader
	if body != nil {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rdr)
	if err != nil {
		return nil, fmt.Errorf("s3: build request: %w", err)
	}
	req.Host = host
	req.URL.RawPath = u.RawPath
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	payloadHash := sigv4.HashSHA256(body)
	c.signer.Sign(req, payloadHash, nowUTC())

	resp, err := c.doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("s3: %s %s: %w", method, key, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		return nil, c.requestError(resp)
	}
	return resp, nil
}

// Get fetches the whole object.
func (c *Client) Get(ctx context.Context, key string) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodGet, key, nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// GetRange fetches length bytes starting at off. A length <= 0 fetches to EOF.
func (c *Client) GetRange(ctx context.Context, key string, off, length int64) ([]byte, error) {
	var rangeHdr string
	if length > 0 {
		rangeHdr = fmt.Sprintf("bytes=%d-%d", off, off+length-1)
	} else {
		rangeHdr = fmt.Sprintf("bytes=%d-", off)
	}
	resp, err := c.do(ctx, http.MethodGet, key, nil, rangeHdr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// Put stores body under key.
func (c *Client) Put(ctx context.Context, key string, body []byte) error {
	if body == nil {
		body = []byte{}
	}
	resp, err := c.do(ctx, http.MethodPut, key, body, "")
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// PutOptions are the optional headers of a PutObject request (Amazon S3 API
// Reference, PutObject).
type PutOptions struct {
	ContentType     string
	ContentEncoding string
	// LockMode, "GOVERNANCE" or "COMPLIANCE", with RetainUntil, puts the
	// object under Object Lock retention (x-amz-object-lock-mode and
	// x-amz-object-lock-retain-until-date). The bucket must have Object Lock
	// enabled (see ObjectLockEnabled), which also needs versioning.
	LockMode    string
	RetainUntil time.Time
}

// PutWithOptions stores body under key with the given headers. It always
// sends Content-MD5 (RFC 1864), which S3 requires for an upload with an
// Object Lock retention period and checks on every other one.
func (c *Client) PutWithOptions(ctx context.Context, key string, body []byte, opts PutOptions) error {
	if body == nil {
		body = []byte{}
	}
	hdr := http.Header{}
	sum := md5.Sum(body)
	hdr.Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
	if opts.ContentType != "" {
		hdr.Set("Content-Type", opts.ContentType)
	}
	if opts.ContentEncoding != "" {
		hdr.Set("Content-Encoding", opts.ContentEncoding)
	}
	if opts.LockMode != "" {
		if opts.LockMode != "GOVERNANCE" && opts.LockMode != "COMPLIANCE" {
			return fmt.Errorf("s3: object lock mode %q: want GOVERNANCE or COMPLIANCE", opts.LockMode)
		}
		if opts.RetainUntil.IsZero() {
			return errors.New("s3: an object lock mode needs a retain-until date")
		}
		hdr.Set("X-Amz-Object-Lock-Mode", opts.LockMode)
		hdr.Set("X-Amz-Object-Lock-Retain-Until-Date", opts.RetainUntil.UTC().Format(time.RFC3339))
	}
	resp, err := c.doWith(ctx, http.MethodPut, key, "", body, hdr)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// ObjectLock is a bucket's Object Lock configuration
// (GetObjectLockConfiguration).
type ObjectLock struct {
	Enabled bool
	// The bucket's default retention, if it has one.
	Mode  string
	Days  int
	Years int
}

// ObjectLockConfiguration reads the bucket's Object Lock configuration
// (GET /?object-lock). A bucket without one — S3 answers 404
// ObjectLockConfigurationNotFoundError, some servers 400 or 501 — is
// reported as not enabled, not as an error.
func (c *Client) ObjectLockConfiguration(ctx context.Context) (ObjectLock, error) {
	resp, err := c.doWith(ctx, http.MethodGet, "", "object-lock", nil, nil)
	if err != nil {
		var se *Error
		if errors.Is(err, ErrNotFound) || errors.As(err, &se) && (se.Code == "ObjectLockConfigurationNotFoundError" || se.StatusCode == http.StatusNotImplemented) {
			return ObjectLock{}, nil
		}
		return ObjectLock{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ObjectLock{}, fmt.Errorf("s3: reading the object lock configuration: %w", err)
	}
	return parseObjectLock(body)
}

func parseObjectLock(body []byte) (ObjectLock, error) {
	var x struct {
		XMLName           xml.Name `xml:"ObjectLockConfiguration"`
		ObjectLockEnabled string
		Rule              struct {
			DefaultRetention struct {
				Mode  string
				Days  int
				Years int
			}
		}
	}
	if err := xml.Unmarshal(body, &x); err != nil {
		return ObjectLock{}, fmt.Errorf("s3: the object lock configuration is not one: %w", err)
	}
	r := x.Rule.DefaultRetention
	return ObjectLock{Enabled: x.ObjectLockEnabled == "Enabled", Mode: r.Mode, Days: r.Days, Years: r.Years}, nil
}

// Delete removes key. A 404 is not an error (delete is idempotent).
func (c *Client) Delete(ctx context.Context, key string) error {
	resp, err := c.do(ctx, http.MethodDelete, key, nil, "")
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	resp.Body.Close()
	return nil
}

// Head returns the object's size (Content-Length) and whether it exists.
// A missing object returns (0, false, nil); other errors are returned.
func (c *Client) Head(ctx context.Context, key string) (size int64, exists bool, err error) {
	resp, err := c.do(ctx, http.MethodHead, key, nil, "")
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return 0, false, nil
		}
		return 0, false, err
	}
	defer resp.Body.Close()
	cl := resp.Header.Get("Content-Length")
	if cl == "" {
		return 0, true, nil
	}
	n, perr := strconv.ParseInt(cl, 10, 64)
	if perr != nil {
		return 0, true, fmt.Errorf("s3: bad Content-Length %q: %w", cl, perr)
	}
	return n, true, nil
}

// Error is a parsed S3 XML error response.
type Error struct {
	StatusCode int
	Code       string `xml:"Code"`
	Message    string `xml:"Message"`
	Resource   string `xml:"Resource"`
	RequestID  string `xml:"RequestId"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("s3: %s (%d): %s", e.Code, e.StatusCode, e.Message)
}

// Is lets errors.Is(err, ErrNotFound) match a NoSuchKey/NoSuchBucket Error.
func (e *Error) Is(target error) bool {
	if target == ErrNotFound {
		return e.StatusCode == http.StatusNotFound ||
			e.Code == "NoSuchKey" || e.Code == "NoSuchBucket"
	}
	return false
}

// parseS3Error decodes an <Error>…</Error> body, or nil if it is not one.
func parseS3Error(body []byte) *Error {
	if len(body) == 0 {
		return nil
	}
	var e Error
	if err := xml.Unmarshal(body, &e); err != nil {
		return nil
	}
	if e.Code == "" {
		return nil
	}
	return &e
}
