// Copyright (c) 2026, the go-volumes/s3 authors
// SPDX-License-Identifier: BSD-3-Clause

package client

import "time"

// nowUTC returns the current time in UTC. It is a package variable so tests can
// pin the signing timestamp deterministically.
var nowUTC = func() time.Time { return time.Now().UTC() }
