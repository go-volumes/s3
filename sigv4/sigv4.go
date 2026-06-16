// Copyright (c) 2026, the go-volumes/s3 authors
// SPDX-License-Identifier: BSD-3-Clause

// Package sigv4 signs HTTP requests with AWS Signature Version 4 using only the
// Go standard library (crypto/sha256, crypto/hmac).
//
// The implementation follows the AWS-documented algorithm exactly so that it
// reproduces the official "Signature Version 4 Test Suite" canonical request,
// string-to-sign, and Authorization header byte-for-byte. See sigv4_test.go.
package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Algorithm is the AWS SigV4 algorithm identifier.
const Algorithm = "AWS4-HMAC-SHA256"

// UnsignedPayload is the value used for X-Amz-Content-Sha256 when the body hash
// is not computed (e.g. streaming uploads).
const UnsignedPayload = "UNSIGNED-PAYLOAD"

// EmptyStringSHA256 is the hex SHA-256 of an empty body.
const EmptyStringSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// Credentials are the access key, secret key, and optional session token used
// to sign a request.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string // optional; sets X-Amz-Security-Token when present
}

// Signer signs *http.Request values for a given region and service.
type Signer struct {
	Region  string
	Service string
	Creds   Credentials
}

// New returns a Signer for the given region/service/credentials.
func New(region, service string, creds Credentials) *Signer {
	return &Signer{Region: region, Service: service, Creds: creds}
}

// HashSHA256 returns the lowercase hex SHA-256 of b.
func HashSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Sign signs req in place at time t with the given payload hash (a lowercase
// hex SHA-256 of the body, or UnsignedPayload). It sets the X-Amz-Date,
// X-Amz-Content-Sha256, (optional) X-Amz-Security-Token, and Authorization
// headers. The Host header is taken from req.Host or req.URL.Host.
//
// Sign returns the SigningResult so callers (and tests) can inspect the
// canonical request and string-to-sign that produced the signature.
func (s *Signer) Sign(req *http.Request, payloadHash string, t time.Time) SigningResult {
	return s.sign(req, payloadHash, t, true)
}

// SignRaw signs req without injecting the S3-specific X-Amz-Content-Sha256
// header: it signs exactly the headers already present on the request plus
// host and x-amz-date. payloadHash is still used as the canonical-request
// payload hash. This reproduces the official AWS SigV4 test-suite vectors,
// which sign neither x-amz-content-sha256 nor the empty-body hash as a header.
func (s *Signer) SignRaw(req *http.Request, payloadHash string, t time.Time) SigningResult {
	return s.sign(req, payloadHash, t, false)
}

func (s *Signer) sign(req *http.Request, payloadHash string, t time.Time, s3Headers bool) SigningResult {
	t = t.UTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	req.Header.Set("X-Amz-Date", amzDate)
	if s3Headers {
		// The standard S3 set also signs the content hash header.
		req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	}
	if s.Creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", s.Creds.SessionToken)
	}

	canonicalHeaders, signedHeaders := canonicalHeaders(req, host)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.EscapedPath()),
		canonicalQuery(req.URL.RawQuery),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, s.Region, s.Service, "aws4_request"}, "/")

	stringToSign := strings.Join([]string{
		Algorithm,
		amzDate,
		scope,
		HashSHA256([]byte(canonicalRequest)),
	}, "\n")

	signingKey := deriveSigningKey(s.Creds.SecretAccessKey, dateStamp, s.Region, s.Service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	authorization := Algorithm +
		" Credential=" + s.Creds.AccessKeyID + "/" + scope +
		", SignedHeaders=" + signedHeaders +
		", Signature=" + signature

	req.Header.Set("Authorization", authorization)

	return SigningResult{
		CanonicalRequest: canonicalRequest,
		StringToSign:     stringToSign,
		Signature:        signature,
		Authorization:    authorization,
		SignedHeaders:    signedHeaders,
		Scope:            scope,
		AmzDate:          amzDate,
	}
}

// SigningResult captures every intermediate product of the signing pipeline.
type SigningResult struct {
	CanonicalRequest string
	StringToSign     string
	Signature        string
	Authorization    string
	SignedHeaders    string
	Scope            string
	AmzDate          string
}

// canonicalHeaders builds the canonical headers block and the signed-headers
// list. The host header is forced from the host argument (net/http keeps Host
// out of the Header map). Header names are lowercased and sorted; values have
// sequential internal whitespace collapsed and surrounding whitespace trimmed.
func canonicalHeaders(req *http.Request, host string) (canonical, signed string) {
	type hv struct {
		name   string
		values []string
	}
	lower := map[string][]string{}
	lower["host"] = []string{host}
	for name, vals := range req.Header {
		ln := strings.ToLower(name)
		// Skip headers AWS never signs unless explicitly requested. We sign all
		// headers we set plus host; that matches S3 client behaviour and the
		// official vectors (which sign exactly the headers present).
		lower[ln] = append(lower[ln], vals...)
	}
	names := make([]string, 0, len(lower))
	for n := range lower {
		names = append(names, n)
	}
	sort.Strings(names)

	var cb strings.Builder
	hvs := make([]hv, 0, len(names))
	for _, n := range names {
		vals := lower[n]
		trimmed := make([]string, len(vals))
		for i, v := range vals {
			trimmed[i] = trimAll(v)
		}
		hvs = append(hvs, hv{name: n, values: trimmed})
	}
	for _, h := range hvs {
		cb.WriteString(h.name)
		cb.WriteByte(':')
		cb.WriteString(strings.Join(h.values, ","))
		cb.WriteByte('\n')
	}
	return cb.String(), strings.Join(names, ";")
}

// trimAll trims surrounding whitespace and collapses runs of internal spaces to
// a single space, per the AWS "Trimall" function.
func trimAll(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	space := false
	for _, r := range s {
		if r == ' ' || r == '\t' {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}

// canonicalURI normalises the (already percent-escaped) path. For S3 the path
// is used as-is after ensuring it begins with "/"; the slash separators are not
// double-encoded. An empty path canonicalises to "/".
func canonicalURI(escapedPath string) string {
	if escapedPath == "" {
		return "/"
	}
	return escapedPath
}

// canonicalQuery sorts query parameters by key (then value) and URI-encodes
// keys and values per RFC 3986 (the AWS rules), joining as k=v&... with every
// key present (even valueless ones get a trailing '=').
func canonicalQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	type kv struct{ k, v string }
	var pairs []kv
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		var k, v string
		if eq < 0 {
			k = part
		} else {
			k = part[:eq]
			v = part[eq+1:]
		}
		// The raw query may already be percent-encoded (e.g. from EscapedPath
		// callers) or raw. We decode loosely then re-encode canonically.
		pairs = append(pairs, kv{k: uriDecode(k), v: uriDecode(v)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		ek, ek2 := uriEncode(pairs[i].k, false), uriEncode(pairs[j].k, false)
		if ek != ek2 {
			return ek < ek2
		}
		return uriEncode(pairs[i].v, false) < uriEncode(pairs[j].v, false)
	})
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(uriEncode(p.k, false))
		b.WriteByte('=')
		b.WriteString(uriEncode(p.v, false))
	}
	return b.String()
}

// uriDecode reverses percent-encoding (best effort; leaves malformed escapes
// untouched).
func uriDecode(s string) string {
	if !strings.ContainsRune(s, '%') {
		// '+' in query strings means space per x-www-form-urlencoded, but for
		// SigV4 canonicalisation AWS treats query values literally; we do not
		// translate '+'.
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			h := fromHex(s[i+1])
			l := fromHex(s[i+2])
			if h >= 0 && l >= 0 {
				b.WriteByte(byte(h<<4 | l))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func fromHex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return -1
}

const upperhex = "0123456789ABCDEF"

// uriEncode percent-encodes s per the AWS SigV4 rules: unreserved characters
// (A-Z a-z 0-9 - _ . ~) are left as-is; everything else is %-encoded with
// uppercase hex. When encodeSlash is false, '/' is also left unencoded (used
// for S3 object keys in the path).
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(upperhex[c>>4])
			b.WriteByte(upperhex[c&0x0f])
		}
	}
	return b.String()
}

// EncodePath percent-encodes an S3 object key into a request path: each segment
// is URI-encoded but the '/' separators are preserved. The returned value
// always begins with '/'.
func EncodePath(key string) string {
	key = strings.TrimPrefix(key, "/")
	segs := strings.Split(key, "/")
	for i, s := range segs {
		segs[i] = uriEncode(s, true)
	}
	return "/" + strings.Join(segs, "/")
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// deriveSigningKey runs the kDate→kRegion→kService→kSigning HMAC chain.
func deriveSigningKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}
