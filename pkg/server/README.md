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

	"github.com/rkojedzinszky/postfix-sasl-exporter/pkg/server"
)

type s struct{}

func (s *s) Handle(ctx context.Context, req *server.Request) string {
	log.Printf("Request=%+v", *req)

	return server.REJECT
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