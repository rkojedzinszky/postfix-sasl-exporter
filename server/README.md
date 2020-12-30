# Postfix policy server

A simple postfix policy server written in Go. It just receives requests from postfix, handles them to a `Handler`, and returns the result to postfix.

Right now only returning an `action` is supported.

## Usage

Example:

```go
package main

import (
	"context"
	"log"
	"net"

	"github.com/rkojedzinszky/postfix-sasl-exporter/server"
)

type s struct{}

func (s *s) Handle(req *server.Request) server.Response {
	// Do anything with request

	return server.Response{Action: server.REJECT}
}

func main() {
	lis, err := net.Listen("tcp", ":10027")
	if err != nil {
		log.Fatal(err)
	}

	ps := &s{}

	server.Run(context.Background(), lis, ps)
}

```