package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type policyServer struct {
	stats map[string]*statEntry
	mu    sync.Mutex
}

func (p *policyServer) Run(ctx context.Context, l net.Listener) {
	wg := &sync.WaitGroup{}

	for {
		conn, err := l.Accept()
		if err != nil {
			break
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			p.handle(ctx, conn)
		}()
	}

	wg.Wait()
}

type policyRequest struct {
	Request                string
	ProtocolState          string
	ProtocolName           string
	HeloName               string
	QueueId                string
	Sender                 string
	Recipient              string
	RecipientCount         string
	ClientAddress          string
	ClientName             string
	ReverseClientName      string
	Instance               string
	SaslMethod             string
	SaslUsername           string
	SaslSender             string
	Size                   string
	CcertSubject           string
	CcertIssuer            string
	CcertFingerprint       string
	EncryptionProtocol     string
	EncryptionCipher       string
	EncryptionKeysize      string
	EtrnDomain             string
	Stress                 string
	CcertPubkeyFingerprint string
	ClientPort             string
	PolicyContext          string
	ServerAddress          string
	ServerPort             string
}

type parameterSetterFunction func(p *policyRequest, v string)

var parameterSetterFunctions map[string]parameterSetterFunction = map[string]parameterSetterFunction{
	"request":                  func(p *policyRequest, v string) { p.Request = v },
	"protocol_state":           func(p *policyRequest, v string) { p.ProtocolState = v },
	"protocol_name":            func(p *policyRequest, v string) { p.ProtocolName = v },
	"helo_name":                func(p *policyRequest, v string) { p.HeloName = v },
	"queue_id":                 func(p *policyRequest, v string) { p.QueueId = v },
	"sender":                   func(p *policyRequest, v string) { p.Sender = v },
	"recipient":                func(p *policyRequest, v string) { p.Recipient = v },
	"recipient_count":          func(p *policyRequest, v string) { p.RecipientCount = v },
	"client_address":           func(p *policyRequest, v string) { p.ClientAddress = v },
	"client_name":              func(p *policyRequest, v string) { p.ClientName = v },
	"reverse_client_name":      func(p *policyRequest, v string) { p.ReverseClientName = v },
	"instance":                 func(p *policyRequest, v string) { p.Instance = v },
	"sasl_method":              func(p *policyRequest, v string) { p.SaslMethod = v },
	"sasl_username":            func(p *policyRequest, v string) { p.SaslUsername = v },
	"sasl_sender":              func(p *policyRequest, v string) { p.SaslSender = v },
	"size":                     func(p *policyRequest, v string) { p.Size = v },
	"ccert_subject":            func(p *policyRequest, v string) { p.CcertSubject = v },
	"ccert_issuer":             func(p *policyRequest, v string) { p.CcertIssuer = v },
	"ccert_fingerprint":        func(p *policyRequest, v string) { p.CcertFingerprint = v },
	"encryption_protocol":      func(p *policyRequest, v string) { p.EncryptionProtocol = v },
	"encryption_cipher":        func(p *policyRequest, v string) { p.EncryptionCipher = v },
	"encryption_keysize":       func(p *policyRequest, v string) { p.EncryptionKeysize = v },
	"etrn_domain":              func(p *policyRequest, v string) { p.EtrnDomain = v },
	"stress":                   func(p *policyRequest, v string) { p.Stress = v },
	"ccert_pubkey_fingerprint": func(p *policyRequest, v string) { p.CcertPubkeyFingerprint = v },
	"client_port":              func(p *policyRequest, v string) { p.ClientPort = v },
	"policy_context":           func(p *policyRequest, v string) { p.PolicyContext = v },
	"server_address":           func(p *policyRequest, v string) { p.ServerAddress = v },
	"server_port":              func(p *policyRequest, v string) { p.ServerPort = v },
}

func (p *policyServer) read(ctx context.Context, r *bufio.Reader) (req *policyRequest, err error) {
	req = &policyRequest{}

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}

		line = strings.TrimRight(line, "\r\n")

		if line == "" {
			break
		}

		splitted := strings.Split(line, "=")
		if len(splitted) != 2 {
			continue
		}

		if setter, ok := parameterSetterFunctions[splitted[0]]; ok {
			setter(req, splitted[1])
		}
	}

	return
}

var (
	reply = []byte("action=dunno\n\n")
)

func (p *policyServer) handle(ctx context.Context, conn net.Conn) {
	done := make(chan bool)
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}

		conn.Close()
	}()

	reader := bufio.NewReader(conn)

	for {
		req, err := p.read(ctx, reader)
		if err != nil {
			return
		}

		p.handleReq(req)

		conn.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write(reply); err != nil {
			log.Printf("Failed writing response: %+v", err)
			return
		}
	}
}

func (p *policyServer) handleReq(req *policyRequest) {
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

	mailSentCounts     = prometheus.NewDesc("postfix_mail_sent_counts", "Total number of mails sent", labels, nil)
	mailSentRecipients = prometheus.NewDesc("postfix_mail_sent_recipients", "Total number of recipients", labels, nil)
	mailSentSizes      = prometheus.NewDesc("postfix_mail_sent_total_size", "Total size of sent mails", labels, nil)
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
