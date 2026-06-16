// Copyright (c) 2026, the go-volumes/s3 authors
// SPDX-License-Identifier: BSD-3-Clause

package sigv4

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// AWS Signature Version 4 Test Suite credentials and parameters.
var (
	testCreds = Credentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}
	testRegion  = "us-east-1"
	testService = "service"
	testTime    = time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
)

// vector describes one official AWS SigV4 test-suite case: the request to build
// and the golden testdata file stem (.creq/.sts/.authz).
type vector struct {
	name    string
	method  string
	rawURL  string
	headers map[string]string
	body    string
}

func vectors() []vector {
	return []vector{
		{
			name:   "get-vanilla",
			method: "GET",
			rawURL: "https://example.amazonaws.com/",
		},
		{
			name:   "get-vanilla-query-order-key-case",
			method: "GET",
			rawURL: "https://example.amazonaws.com/?Param2=value2&Param1=value1",
		},
		{
			name:    "get-header-value-trim",
			method:  "GET",
			rawURL:  "https://example.amazonaws.com/",
			headers: map[string]string{"My-Header1": "  value1 "},
		},
		{
			name:    "post-x-www-form-urlencoded",
			method:  "POST",
			rawURL:  "https://example.amazonaws.com/",
			headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			body:    "Param1=value1",
		},
		{
			name:   "get-utf8",
			method: "GET",
			rawURL: "https://example.amazonaws.com/ሴ",
		},
	}
}

func golden(t *testing.T, stem, ext string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", stem+"."+ext))
	if err != nil {
		t.Fatalf("read golden %s.%s: %v", stem, ext, err)
	}
	return string(b)
}

func TestOfficialVectors(t *testing.T) {
	s := New(testRegion, testService, testCreds)
	for _, v := range vectors() {
		t.Run(v.name, func(t *testing.T) {
			req, err := http.NewRequest(v.method, v.rawURL, strings.NewReader(v.body))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			for k, val := range v.headers {
				req.Header.Set(k, val)
			}
			payloadHash := HashSHA256([]byte(v.body))

			// The official vectors sign exactly host + x-amz-date + the headers
			// present, without the S3 x-amz-content-sha256 header.
			res := s.SignRaw(req, payloadHash, testTime)

			if got, want := res.CanonicalRequest, golden(t, v.name, "creq"); got != want {
				t.Errorf("canonical request mismatch\n--- got ---\n%q\n--- want ---\n%q", got, want)
			}
			if got, want := res.StringToSign, golden(t, v.name, "sts"); got != want {
				t.Errorf("string-to-sign mismatch\n--- got ---\n%q\n--- want ---\n%q", got, want)
			}
			if got, want := res.Authorization, golden(t, v.name, "authz"); got != want {
				t.Errorf("authorization mismatch\n--- got ---\n%q\n--- want ---\n%q", got, want)
			}
		})
	}
}

// TestGetVanillaKnownGood pins the get-vanilla signature to the value AWS
// publishes in its documentation, proving the HMAC chain end-to-end against an
// external reference (not self-consistency).
func TestGetVanillaKnownGood(t *testing.T) {
	const wantSig = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	const wantSTSHash = "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"

	s := New(testRegion, testService, testCreds)
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	res := s.SignRaw(req, EmptyStringSHA256, testTime)
	if res.Signature != wantSig {
		t.Fatalf("signature = %s, want %s", res.Signature, wantSig)
	}
	if !strings.HasSuffix(res.StringToSign, wantSTSHash) {
		t.Fatalf("STS does not end with known-good creq hash %s:\n%s", wantSTSHash, res.StringToSign)
	}
	// Pin the derived signing key to the AWS-documented intermediate value.
	const wantKey = "938127b5336810ddb6a5d6af445fcac9e371f9ed418ed386b022aed82901be75"
	key := deriveSigningKey(testCreds.SecretAccessKey, "20150830", testRegion, testService)
	if got := hexOf(key); got != wantKey {
		t.Fatalf("signing key = %s, want %s", got, wantKey)
	}
}

func hexOf(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = h[c>>4]
		out[i*2+1] = h[c&0xf]
	}
	return string(out)
}

func TestSignSetsS3Headers(t *testing.T) {
	s := New("us-east-1", "s3", testCreds)
	req, _ := http.NewRequest("PUT", "https://bucket.s3.amazonaws.com/key", strings.NewReader("data"))
	res := s.Sign(req, UnsignedPayload, testTime)
	if req.Header.Get("X-Amz-Content-Sha256") != UnsignedPayload {
		t.Errorf("X-Amz-Content-Sha256 not set to UNSIGNED-PAYLOAD")
	}
	if req.Header.Get("X-Amz-Date") == "" {
		t.Errorf("X-Amz-Date not set")
	}
	if !strings.Contains(res.SignedHeaders, "x-amz-content-sha256") {
		t.Errorf("x-amz-content-sha256 not in signed headers: %s", res.SignedHeaders)
	}
	if !strings.Contains(res.Authorization, "Credential=AKIDEXAMPLE/") {
		t.Errorf("authorization missing credential: %s", res.Authorization)
	}
}

func TestSignSessionToken(t *testing.T) {
	creds := testCreds
	creds.SessionToken = "FQoSESSIONTOKEN"
	s := New("us-east-1", "s3", creds)
	req, _ := http.NewRequest("GET", "https://bucket.s3.amazonaws.com/k", nil)
	res := s.Sign(req, EmptyStringSHA256, testTime)
	if req.Header.Get("X-Amz-Security-Token") != "FQoSESSIONTOKEN" {
		t.Errorf("security token header not set")
	}
	if !strings.Contains(res.SignedHeaders, "x-amz-security-token") {
		t.Errorf("session token not signed: %s", res.SignedHeaders)
	}
}

func TestSignHostFromURL(t *testing.T) {
	s := New("us-east-1", "s3", testCreds)
	req, _ := http.NewRequest("GET", "https://h.example.com/p", nil)
	req.Host = "" // force fallback to URL.Host
	res := s.Sign(req, EmptyStringSHA256, testTime)
	if !strings.Contains(res.CanonicalRequest, "host:h.example.com\n") {
		t.Errorf("host not taken from URL: %s", res.CanonicalRequest)
	}
}

func TestCanonicalURIEmpty(t *testing.T) {
	if got := canonicalURI(""); got != "/" {
		t.Errorf("canonicalURI(\"\") = %q, want /", got)
	}
}

func TestCanonicalQueryEmpty(t *testing.T) {
	if got := canonicalQuery(""); got != "" {
		t.Errorf("canonicalQuery(\"\") = %q, want empty", got)
	}
}

func TestCanonicalQueryValueless(t *testing.T) {
	// A key with no value gets a trailing '=' and keys sort.
	if got := canonicalQuery("b&a=1"); got != "a=1&b=" {
		t.Errorf("canonicalQuery = %q, want a=1&b=", got)
	}
	// Empty segments (double &) are skipped.
	if got := canonicalQuery("a=1&&b=2"); got != "a=1&b=2" {
		t.Errorf("canonicalQuery with empty segment = %q", got)
	}
}

func TestCanonicalQueryEncoding(t *testing.T) {
	// Spaces and reserved chars get percent-encoded; sorting is on encoded keys.
	if got := canonicalQuery("name=a b&x=*"); got != "name=a%20b&x=%2A" {
		t.Errorf("canonicalQuery encoding = %q", got)
	}
}

func TestCanonicalQueryValueSort(t *testing.T) {
	if got := canonicalQuery("k=2&k=1"); got != "k=1&k=2" {
		t.Errorf("value sort = %q, want k=1&k=2", got)
	}
}

func TestURIDecode(t *testing.T) {
	if got := uriDecode("a%20b"); got != "a b" {
		t.Errorf("uriDecode = %q", got)
	}
	if got := uriDecode("plain"); got != "plain" {
		t.Errorf("uriDecode plain = %q", got)
	}
	// Malformed trailing escape is left untouched.
	if got := uriDecode("a%2"); got != "a%2" {
		t.Errorf("uriDecode malformed = %q", got)
	}
	// Invalid hex digit left untouched.
	if got := uriDecode("a%zzb"); got != "a%zzb" {
		t.Errorf("uriDecode invalid hex = %q", got)
	}
}

func TestFromHex(t *testing.T) {
	cases := map[byte]int{'0': 0, '9': 9, 'A': 10, 'F': 15, 'a': 10, 'f': 15, 'g': -1, '/': -1}
	for in, want := range cases {
		if got := fromHex(in); got != want {
			t.Errorf("fromHex(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestEncodePath(t *testing.T) {
	cases := map[string]string{
		"foo/bar":        "/foo/bar",
		"/foo/bar":       "/foo/bar",
		"a b/c+d":        "/a%20b/c%2Bd",
		"vol/000001":     "/vol/000001",
		"k/with~tilde":   "/k/with~tilde",
		"seg/with/slash": "/seg/with/slash",
	}
	for in, want := range cases {
		if got := EncodePath(in); got != want {
			t.Errorf("EncodePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUriEncodeSlash(t *testing.T) {
	if got := uriEncode("a/b", true); got != "a%2Fb" {
		t.Errorf("uriEncode encodeSlash = %q, want a%%2Fb", got)
	}
	if got := uriEncode("a/b", false); got != "a/b" {
		t.Errorf("uriEncode keepSlash = %q, want a/b", got)
	}
}

func TestTrimAll(t *testing.T) {
	cases := map[string]string{
		"  value1 ":   "value1",
		"a   b":       "a b",
		"a\tb":        "a b",
		"  a  b  c  ": "a b c",
		"":            "",
		"single":      "single",
	}
	for in, want := range cases {
		if got := trimAll(in); got != want {
			t.Errorf("trimAll(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHashSHA256(t *testing.T) {
	if got := HashSHA256(nil); got != EmptyStringSHA256 {
		t.Errorf("empty hash = %s, want %s", got, EmptyStringSHA256)
	}
}
