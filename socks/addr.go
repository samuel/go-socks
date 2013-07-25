// Copyright 2012 Samuel Stauffer. All rights reserved.
// Use of this source code is governed by a 3-clause BSD
// license that can be found in the LICENSE file.

package socks

import "fmt"

type proxiedAddr struct {
	net  string
	host string
	port int
}

func (a *proxiedAddr) Network() string {
	return a.net
}

func (a *proxiedAddr) String() string {
	return fmt.Sprintf("%s:%d", a.host, a.port)
}
