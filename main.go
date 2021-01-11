package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/namsral/flag"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rkojedzinszky/postfix-sasl-exporter/server"
)

type policyServer struct {
	stats map[string]*statEntry
	mu    sync.Mutex
}

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
		server.Run(ctx, policyListener, pserver)
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

type statEntry struct {
	last time.Time

	// key fields
	saslMethod    string
	saslUsername  string
	serverAddress string
	serverPort    string

	mails      uint64
	recipients uint64
	size       uint64
}

func (s *statEntry) getLabelValues() []string {
	return []string{s.saslMethod, s.saslUsername, s.serverAddress, s.serverPort}
}

func (p *policyServer) lookupStatEntry(saslMethod, saslUsername, serverAddress, serverPort string) *statEntry {
	saslUsername = strings.ToLower(saslUsername)

	key := fmt.Sprintf("%s-%s-%s-%s", saslMethod, serverAddress, serverPort, saslUsername)

	p.mu.Lock()
	defer p.mu.Unlock()

	se, ok := p.stats[key]
	if !ok {
		se = &statEntry{
			saslMethod:    saslMethod,
			saslUsername:  saslUsername,
			serverAddress: serverAddress,
			serverPort:    serverPort,
		}
		p.stats[key] = se
	}
	se.last = time.Now()

	return se
}

// Prometheus metrics
var (
	labels = []string{"sasl_method", "sasl_username", "server_address", "server_port"}

	mailSentCounts     = prometheus.NewDesc("postfix_mail_sent_mails", "Total number of mails sent", labels, nil)
	mailSentRecipients = prometheus.NewDesc("postfix_mail_sent_recipients", "Total number of recipients", labels, nil)
	mailSentSizes      = prometheus.NewDesc("postfix_mail_sent_size", "Total size of mails sent", labels, nil)
)

func (p *policyServer) Describe(desc chan<- *prometheus.Desc) {
	desc <- mailSentCounts
	desc <- mailSentRecipients
	desc <- mailSentSizes
}

func (p *policyServer) Collect(m chan<- prometheus.Metric) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, s := range p.stats {
		labelValues := s.getLabelValues()

		m <- prometheus.MustNewConstMetric(mailSentCounts, prometheus.CounterValue, float64(s.mails), labelValues...)
		m <- prometheus.MustNewConstMetric(mailSentRecipients, prometheus.CounterValue, float64(s.recipients), labelValues...)
		m <- prometheus.MustNewConstMetric(mailSentSizes, prometheus.CounterValue, float64(s.size), labelValues...)
	}
}

func (p *policyServer) Handle(req *server.Request) (resp string) {
	resp = server.DUNNO

	if req.SaslUsername == "" {
		return
	}

	recipients, err := strconv.ParseUint(req.RecipientCount, 0, 64)
	if err != nil {
		log.Printf("Invalid request: %+v", req)
		return
	}

	size, err := strconv.ParseUint(req.Size, 0, 64)
	if err != nil {
		log.Printf("Invalid request: %+v", req)
		return
	}

	se := p.lookupStatEntry(req.SaslMethod, req.SaslUsername, req.ServerAddress, req.ServerPort)

	atomic.AddUint64(&se.mails, 1)
	atomic.AddUint64(&se.recipients, recipients)
	atomic.AddUint64(&se.size, size)

	return
}
