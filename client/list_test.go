// Copyright (c) 2026, the go-volumes/s3 authors
// SPDX-License-Identifier: BSD-3-Clause

package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// listPage answers like ListObjectsV2 (Amazon S3 API Reference examples).
func listPage(keys []string, next string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>bkt</Name>`)
	fmt.Fprintf(&b, "<IsTruncated>%v</IsTruncated>", next != "")
	if next != "" {
		fmt.Fprintf(&b, "<NextContinuationToken>%s</NextContinuationToken>", next)
	}
	for i, k := range keys {
		fmt.Fprintf(&b, `<Contents><Key>%s</Key><LastModified>2009-10-12T17:50:30.000Z</LastModified><ETag>"e%d"</ETag><Size>%d</Size><StorageClass>STANDARD</StorageClass></Contents>`, k, i, i+1)
	}
	b.WriteString("</ListBucketResult>")
	return b.String()
}

func TestList(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		if r.URL.Path != "/bkt" || r.URL.Query().Get("list-type") != "2" || r.URL.Query().Get("prefix") != "audit/check points/" {
			t.Errorf("asked %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		switch r.URL.Query().Get("continuation-token") {
		case "":
			io.WriteString(w, listPage([]string{"audit/check points/0001", "audit/check points/0002"}, "tok+/="))
		case "tok+/=":
			io.WriteString(w, listPage([]string{"audit/check points/0003"}, ""))
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	objs, err := c.List(context.Background(), "audit/check points/", 0)
	if err != nil || len(objs) != 3 || objs[2].Key != "audit/check points/0003" || objs[1].Size != 2 || objs[0].ETag != `"e0"` || objs[0].LastModified.Year() != 2009 {
		t.Fatalf("%+v %v", objs, err)
	}
	if !strings.Contains(queries[0], "prefix=audit%2Fcheck%20points%2F") || !strings.Contains(queries[1], "continuation-token=tok%2B%2F%3D") {
		t.Fatalf("queries %v", queries)
	}
	if objs, err := c.List(context.Background(), "audit/check points/", 1); err != nil || len(objs) != 1 {
		t.Fatalf("limit: %+v %v", objs, err)
	}
}

func TestListRefusals(t *testing.T) {
	var answer string
	code := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		io.WriteString(w, answer)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	ctx := context.Background()
	for name, a := range map[string]string{
		"not a listing":              `<Other/>`,
		"bad size":                   `<ListBucketResult><Contents><Key>k</Key><Size>-1</Size></Contents></ListBucketResult>`,
		"bad date":                   `<ListBucketResult><Contents><Key>k</Key><LastModified>yesterday</LastModified></Contents></ListBucketResult>`,
		"truncated without a token":  `<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>`,
		"a token that does not move": `<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>t</NextContinuationToken></ListBucketResult>`,
	} {
		answer = a
		if name == "a token that does not move" {
			// The first page moves to "t", the second answers "t" again.
			calls := 0
			srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				io.WriteString(w, a)
			})
		}
		if _, err := c.List(ctx, "", 0); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		io.WriteString(w, s3ErrorXML("NoSuchBucket", "no"))
	})
	if _, err := c.List(ctx, "", 0); err == nil {
		t.Error("a missing bucket listed")
	}
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<ListBucketResult>`+strings.Repeat(" ", maxListPage+1))
	})
	if _, err := c.List(ctx, "", 0); err == nil {
		t.Error("an oversized page accepted")
	}
	cr, _ := New(Config{Endpoint: "http://127.0.0.1:1", Region: "r", Bucket: "b", AccessKey: "a", SecretKey: "s", PathStyle: true, HTTPClient: bodyDoer{200}})
	if _, err := cr.List(ctx, "", 0); err == nil {
		t.Error("an unreadable page accepted")
	}
}

// FuzzParseList: any document parses or is refused; a parsed object never
// has a negative size.
func FuzzParseList(f *testing.F) {
	f.Add(listPage([]string{"a", "b"}, "n"))
	f.Add(`<ListBucketResult><Contents><Size>9223372036854775808</Size></Contents></ListBucketResult>`)
	f.Add(`<ListBucketResult><Contents/><Contents/></ListBucketResult>`)
	f.Fuzz(func(t *testing.T, s string) {
		objs, _, _, err := parseList([]byte(s))
		for _, o := range objs {
			if err == nil && o.Size < 0 {
				t.Fatalf("negative size from %q", s)
			}
		}
	})
}
