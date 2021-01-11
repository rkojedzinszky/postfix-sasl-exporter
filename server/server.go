package server

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// Request holds a policy request
type Request struct {
	Request                string
	ProtocolState          string
	ProtocolName           string
	HeloName               string
	QueueID                string
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

// Values for Action
const (
	ACCEPT          = "OK"
	REJECT          = "REJECT"
	DEFER           = "DEFER"
	DEFER_IF_REJECT = "DEFER_IF_REJECT"
	DEFER_IF_PERMIT = "DEFER_IF_PERMIT"
	DISCARD         = "DISCARD"
	DUNNO           = "DUNNO"
	HOLD            = "HOLD"
	INFO            = "INFO"
	WARN            = "WARN"
)

// Handler interface for handling policy requests
type Handler interface {
	Handle(r *Request) string
}

// Run runs a policy listener. On context close waits for all goroutines to finish, then returns.
func Run(ctx context.Context, l net.Listener, h Handler) {
	wg := &sync.WaitGroup{}

	for {
		conn, err := l.Accept()
		if err != nil {
			break
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			handleConnection(ctx, conn, h)
		}()
	}

	wg.Wait()
}

type parameterSetterFunction func(p *Request, v string)

var parameterSetterFunctions map[string]parameterSetterFunction = map[string]parameterSetterFunction{
	"request":                  func(p *Request, v string) { p.Request = v },
	"protocol_state":           func(p *Request, v string) { p.ProtocolState = v },
	"protocol_name":            func(p *Request, v string) { p.ProtocolName = v },
	"helo_name":                func(p *Request, v string) { p.HeloName = v },
	"queue_id":                 func(p *Request, v string) { p.QueueID = v },
	"sender":                   func(p *Request, v string) { p.Sender = v },
	"recipient":                func(p *Request, v string) { p.Recipient = v },
	"recipient_count":          func(p *Request, v string) { p.RecipientCount = v },
	"client_address":           func(p *Request, v string) { p.ClientAddress = v },
	"client_name":              func(p *Request, v string) { p.ClientName = v },
	"reverse_client_name":      func(p *Request, v string) { p.ReverseClientName = v },
	"instance":                 func(p *Request, v string) { p.Instance = v },
	"sasl_method":              func(p *Request, v string) { p.SaslMethod = v },
	"sasl_username":            func(p *Request, v string) { p.SaslUsername = v },
	"sasl_sender":              func(p *Request, v string) { p.SaslSender = v },
	"size":                     func(p *Request, v string) { p.Size = v },
	"ccert_subject":            func(p *Request, v string) { p.CcertSubject = v },
	"ccert_issuer":             func(p *Request, v string) { p.CcertIssuer = v },
	"ccert_fingerprint":        func(p *Request, v string) { p.CcertFingerprint = v },
	"encryption_protocol":      func(p *Request, v string) { p.EncryptionProtocol = v },
	"encryption_cipher":        func(p *Request, v string) { p.EncryptionCipher = v },
	"encryption_keysize":       func(p *Request, v string) { p.EncryptionKeysize = v },
	"etrn_domain":              func(p *Request, v string) { p.EtrnDomain = v },
	"stress":                   func(p *Request, v string) { p.Stress = v },
	"ccert_pubkey_fingerprint": func(p *Request, v string) { p.CcertPubkeyFingerprint = v },
	"client_port":              func(p *Request, v string) { p.ClientPort = v },
	"policy_context":           func(p *Request, v string) { p.PolicyContext = v },
	"server_address":           func(p *Request, v string) { p.ServerAddress = v },
	"server_port":              func(p *Request, v string) { p.ServerPort = v },
}

func readRequest(ctx context.Context, r *bufio.Reader) (req *Request, err error) {
	req = &Request{}

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

func handleConnection(ctx context.Context, conn net.Conn, h Handler) {
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
		req, err := readRequest(ctx, reader)
		if err != nil {
			return
		}

		resp := h.Handle(req)

		conn.SetWriteDeadline(time.Now().Add(time.Second))
		reply := []byte(fmt.Sprintf("action=%s\n\n", resp))
		if _, err := conn.Write(reply); err != nil {
			log.Printf("Failed writing response: %+v", err)
			return
		}
	}
}
