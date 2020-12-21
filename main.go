package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/namsral/flag"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	policyListenAddress := flag.String("policy-listen-address", ":10026", "Postfix Policy listen address")
	webListenAddress := flag.String("web-listen-address", ":9026", "Exporter WEB listen address")

	flag.Parse()

	policyListener, err := net.Listen("tcp", *policyListenAddress)
	if err != nil {
		log.Fatal(err)
	}

	webListener, err := net.Listen("tcp", *webListenAddress)
	if err != nil {
		log.Fatal(err)
	}

	pserver := &policyServer{
		stats: make(map[string]*statEntry),
	}

	prometheus.Register(pserver)

	ctx := context.Background()

	wg := &sync.WaitGroup{}

	wg.Add(2)
	go func() {
		defer wg.Done()
		pserver.Run(ctx, policyListener)
	}()

	go func() {
		defer wg.Done()
		webListen(ctx, webListener)
	}()

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGTERM, syscall.SIGINT)

	<-sigchan

	policyListener.Close()
	webListener.Close()

	wg.Wait()
}

func webListen(ctx context.Context, l net.Listener) {
	mux := http.NewServeMux()

	mux.Handle("/metrics", promhttp.Handler())

	server := http.Server{Handler: mux}

	server.Serve(l)
}
