// Copyright (c) 2026, the go-volumes/s3 authors
// SPDX-License-Identifier: BSD-3-Clause

package client

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Object is one entry of a listing.
type Object struct {
	Key          string
	Size         int64
	LastModified time.Time
	ETag         string
}

// maxListPage bounds one ListObjectsV2 answer read into memory.
const maxListPage = 8 << 20

// List returns the keys under prefix, in the lexicographic order S3 lists
// them (ListObjectsV2, GET /?list-type=2), following continuation tokens
// until the listing ends or limit keys are read (limit <= 0: no limit).
func (c *Client) List(ctx context.Context, prefix string, limit int) ([]Object, error) {
	var out []Object
	token := ""
	for page := 0; ; page++ {
		q := "list-type=2&prefix=" + queryEscape(prefix)
		if token != "" {
			q += "&continuation-token=" + queryEscape(token)
		}
		resp, err := c.doWith(ctx, http.MethodGet, "", q, nil, nil)
		if err != nil {
			return out, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxListPage+1))
		resp.Body.Close()
		if err != nil {
			return out, fmt.Errorf("s3: reading a listing: %w", err)
		}
		if len(body) > maxListPage {
			return out, errors.New("s3: a listing page is larger than 8 MiB")
		}
		objs, next, truncated, err := parseList(body)
		if err != nil {
			return out, err
		}
		out = append(out, objs...)
		if limit > 0 && len(out) >= limit {
			return out[:limit], nil
		}
		if !truncated {
			return out, nil
		}
		if next == "" || next == token {
			return out, errors.New("s3: a truncated listing without a new continuation token")
		}
		token = next
	}
}

// queryEscape encodes a query value as SigV4 canonicalises it: %20 for a
// space, every reserved character escaped.
func queryEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func parseList(body []byte) (objs []Object, next string, truncated bool, err error) {
	var x struct {
		XMLName               xml.Name `xml:"ListBucketResult"`
		IsTruncated           bool
		NextContinuationToken string
		Contents              []struct {
			Key          string
			Size         string
			LastModified string
			ETag         string
		}
	}
	if err := xml.Unmarshal(body, &x); err != nil {
		return nil, "", false, fmt.Errorf("s3: the listing is not one: %w", err)
	}
	for _, c := range x.Contents {
		o := Object{Key: c.Key, ETag: c.ETag}
		if c.Size != "" {
			n, err := strconv.ParseInt(c.Size, 10, 64)
			if err != nil || n < 0 {
				return nil, "", false, fmt.Errorf("s3: a listed object of size %q", c.Size)
			}
			o.Size = n
		}
		if c.LastModified != "" {
			t, err := time.Parse(time.RFC3339Nano, c.LastModified)
			if err != nil {
				return nil, "", false, fmt.Errorf("s3: a listed object modified %q", c.LastModified)
			}
			o.LastModified = t
		}
		objs = append(objs, o)
	}
	return objs, x.NextContinuationToken, x.IsTruncated, nil
}
