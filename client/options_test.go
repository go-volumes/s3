// Copyright (c) 2026, the go-volumes/s3 authors
// SPDX-License-Identifier: BSD-3-Clause

package client

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A PutObject with options carries, and signs, Content-MD5, the content
// headers and the Object Lock headers (Amazon S3 API Reference, PutObject).
func TestPutWithOptions(t *testing.T) {
	var got *http.Request
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, body = r, nil
		body, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	until := time.Date(2033, 1, 2, 3, 4, 5, 0, time.FixedZone("CET", 3600))
	data := []byte("audit segment")
	err := c.PutWithOptions(context.Background(), "audit/2026/seg-1.jsonl.gz", data, PutOptions{
		ContentType: "application/x-ndjson", ContentEncoding: "gzip", LockMode: "COMPLIANCE", RetainUntil: until,
	})
	if err != nil {
		t.Fatal(err)
	}
	sum := md5.Sum(data)
	for h, want := range map[string]string{
		"Content-Md5":                         base64.StdEncoding.EncodeToString(sum[:]),
		"Content-Type":                        "application/x-ndjson",
		"Content-Encoding":                    "gzip",
		"X-Amz-Object-Lock-Mode":              "COMPLIANCE",
		"X-Amz-Object-Lock-Retain-Until-Date": "2033-01-02T02:04:05Z",
	} {
		if v := got.Header.Get(h); v != want {
			t.Errorf("%s = %q, want %q", h, v, want)
		}
	}
	auth := got.Header.Get("Authorization")
	for _, h := range []string{"content-md5", "content-type", "content-encoding", "x-amz-object-lock-mode", "x-amz-object-lock-retain-until-date"} {
		if !strings.Contains(auth, h) {
			t.Errorf("%s is not signed: %s", h, auth)
		}
	}
	if got.Method != http.MethodPut || got.URL.Path != "/bkt/audit/2026/seg-1.jsonl.gz" || string(body) != string(data) {
		t.Fatalf("%s %s %q", got.Method, got.URL.Path, body)
	}

	// Plain puts carry Content-MD5 too; a lock mode is checked.
	if err := c.PutWithOptions(context.Background(), "k", nil, PutOptions{}); err != nil || got.Header.Get("X-Amz-Object-Lock-Mode") != "" || got.Header.Get("Content-Md5") == "" {
		t.Fatalf("plain put: %v %v", err, got.Header)
	}
	for _, o := range []PutOptions{{LockMode: "FOREVER", RetainUntil: until}, {LockMode: "GOVERNANCE"}} {
		if err := c.PutWithOptions(context.Background(), "k", data, o); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
}

func TestObjectLockConfiguration(t *testing.T) {
	var answer func(w http.ResponseWriter)
	var path, query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, query = r.URL.Path, r.URL.RawQuery
		answer(w)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	ctx := context.Background()

	answer = func(w http.ResponseWriter) {
		io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>365</Days></DefaultRetention></Rule></ObjectLockConfiguration>`)
	}
	ol, err := c.ObjectLockConfiguration(ctx)
	if err != nil || !ol.Enabled || ol.Mode != "COMPLIANCE" || ol.Days != 365 {
		t.Fatalf("%+v %v", ol, err)
	}
	if path != "/bkt" || query != "object-lock" {
		t.Fatalf("asked %s?%s", path, query)
	}
	// No configuration, as AWS and MinIO answer it, and as servers without
	// the feature do.
	for _, a := range []func(w http.ResponseWriter){
		func(w http.ResponseWriter) {
			w.WriteHeader(404)
			io.WriteString(w, s3ErrorXML("ObjectLockConfigurationNotFoundError", "Object Lock configuration does not exist for this bucket"))
		},
		func(w http.ResponseWriter) {
			w.WriteHeader(400)
			io.WriteString(w, s3ErrorXML("ObjectLockConfigurationNotFoundError", "none"))
		},
		func(w http.ResponseWriter) { w.WriteHeader(501); io.WriteString(w, s3ErrorXML("NotImplemented", "no")) },
	} {
		answer = a
		if ol, err := c.ObjectLockConfiguration(ctx); err != nil || ol.Enabled {
			t.Errorf("no configuration: %+v %v", ol, err)
		}
	}
	answer = func(w http.ResponseWriter) { w.WriteHeader(403); io.WriteString(w, s3ErrorXML("AccessDenied", "no")) }
	if _, err := c.ObjectLockConfiguration(ctx); err == nil {
		t.Error("access denied read as no configuration")
	}
	answer = func(w http.ResponseWriter) { io.WriteString(w, `<NotTheRightRoot/>`) }
	if _, err := c.ObjectLockConfiguration(ctx); err == nil {
		t.Error("a wrong document accepted")
	}

	// Virtual-host addressing asks the bucket host for "/".
	rec := &recordDoer{}
	vc, err := New(Config{Endpoint: "https://s3.example.org", Region: "r", Bucket: "bkt", AccessKey: "a", SecretKey: "s", HTTPClient: rec})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = vc.ObjectLockConfiguration(ctx)
	if rec.req.URL.Host != "bkt.s3.example.org" || rec.req.URL.Path != "/" || rec.req.URL.RawQuery != "object-lock" {
		t.Fatalf("virtual host: %s", rec.req.URL)
	}
}

type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (errBody) Close() error             { return nil }

type bodyDoer struct{ code int }

func (d bodyDoer) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: d.code, Body: errBody{}, Header: http.Header{}}, nil
}

func TestOptionsErrors(t *testing.T) {
	ctx := context.Background()
	c, err := New(Config{Endpoint: "http://127.0.0.1:1", Region: "r", Bucket: "b", AccessKey: "a", SecretKey: "s", PathStyle: true, HTTPClient: bodyDoer{500}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.PutWithOptions(ctx, "k", []byte("x"), PutOptions{}); err == nil {
		t.Error("a 500 on put accepted")
	}
	c, _ = New(Config{Endpoint: "http://127.0.0.1:1", Region: "r", Bucket: "b", AccessKey: "a", SecretKey: "s", PathStyle: true, HTTPClient: bodyDoer{200}})
	if _, err := c.ObjectLockConfiguration(ctx); err == nil {
		t.Error("an unreadable configuration accepted")
	}
}

// FuzzParseObjectLock: any document either parses or is refused; nothing
// panics, and only "Enabled" enables.
func FuzzParseObjectLock(f *testing.F) {
	f.Add(`<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Years>1</Years></DefaultRetention></Rule></ObjectLockConfiguration>`)
	f.Add(`<ObjectLockConfiguration/>`)
	f.Add(`<ObjectLockConfiguration><Rule><DefaultRetention><Days>99999999999999999999</Days></DefaultRetention></Rule></ObjectLockConfiguration>`)
	f.Add(`<!DOCTYPE x [<!ENTITY a "aaaa">]><ObjectLockConfiguration>&a;</ObjectLockConfiguration>`)
	f.Fuzz(func(t *testing.T, s string) {
		ol, err := parseObjectLock([]byte(s))
		if err == nil && ol.Enabled && !strings.Contains(s, "Enabled") {
			t.Fatalf("enabled without saying so: %q", s)
		}
	})
}

// FuzzParseS3Error: any error body parses or is ignored, never panics.
func FuzzParseS3Error(f *testing.F) {
	f.Add(s3ErrorXML("NoSuchKey", "x"))
	f.Add(`<Error><Code></Code></Error>`)
	f.Add(`<Error><Code>A</Code><Message>` + strings.Repeat("m", 1000) + `</Message></Error>`)
	f.Add(``)
	f.Fuzz(func(t *testing.T, s string) {
		if e := parseS3Error([]byte(s)); e != nil && e.Code == "" {
			t.Fatalf("an error without a code: %q", s)
		}
	})
}
