package lab

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"felix/pkg/oast"
	"golang.org/x/net/dns/dnsmessage"
)

// MockOASTServer encapsulates a fully functional local DNS and HTTP callback server for lab testing.
type MockOASTServer struct {
	Listener   *oast.Listener
	Correlator *oast.Correlator
	Domain     string
	HTTPURL    string
	DNSAddr    *net.UDPAddr
	client     *http.Client
	mu         sync.Mutex
}

// NewMockOASTServer initializes and starts a local loopback OAST server on ephemeral ports.
func NewMockOASTServer(domain string) (*MockOASTServer, error) {
	return NewMockOASTServerWithConfig(domain, 10000, 30*time.Second)
}

// NewMockOASTServerWithConfig initializes a local OAST server with explicit capacity and TTL bounds.
func NewMockOASTServerWithConfig(domain string, maxProbes int, defaultTTL time.Duration) (*MockOASTServer, error) {
	if domain == "" {
		domain = "oast.felix.internal"
	}
	if defaultTTL <= 0 {
		defaultTTL = 30 * time.Second
	}
	if maxProbes <= 0 {
		maxProbes = 10000
	}

	correlatorCfg := oast.DefaultConfig()
	correlatorCfg.AllowLoopback = true
	correlatorCfg.OASTDomain = domain
	correlatorCfg.DefaultTTL = defaultTTL
	correlatorCfg.MaxProbes = maxProbes

	correlator, err := oast.NewCorrelator(correlatorCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create correlator: %w", err)
	}

	listenerCfg := oast.ListenerConfig{
		OASTDomain:    domain,
		HTTPBindAddr:  "127.0.0.1:0",
		DNSBindAddr:   "127.0.0.1:0",
		ResponseIPv4:  net.ParseIP("127.0.0.1"),
		DefaultTTL:    defaultTTL,
		MaxBodyBytes:  64 * 1024,
		MaxProbes:     maxProbes,
		AllowLoopback: true,
	}

	listener, err := oast.NewListener(listenerCfg, correlator)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	if err := listener.Start(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to start listener: %w", err)
	}

	httpAddr := listener.HTTPAddr().String()
	httpURL := fmt.Sprintf("http://%s", httpAddr)

	return &MockOASTServer{
		Listener:   listener,
		Correlator: correlator,
		Domain:     domain,
		HTTPURL:    httpURL,
		DNSAddr:    listener.DNSAddr(),
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}, nil
}

// RegisterProbe registers an explicit probe tied to a finding ID, template ID, and probe type.
func (s *MockOASTServer) RegisterProbe(findingID, templateID, probeType string) (*oast.Probe, error) {
	return s.Listener.RegisterProbe(oast.ProbeOptions{
		FindingID:  findingID,
		TemplateID: templateID,
		ProbeType:  probeType,
		TargetURL:  s.HTTPURL,
		OASTDomain: s.Domain,
		TTL:        0, // Uses configured DefaultTTL
	})
}

// RegisterProbeWithTTL registers a probe with a custom time-to-live.
func (s *MockOASTServer) RegisterProbeWithTTL(findingID, templateID, probeType string, ttl time.Duration) (*oast.Probe, error) {
	return s.Listener.RegisterProbe(oast.ProbeOptions{
		FindingID:  findingID,
		TemplateID: templateID,
		ProbeType:  probeType,
		TargetURL:  s.HTTPURL,
		OASTDomain: s.Domain,
		TTL:        ttl,
	})
}

// SimulateDNSQuery sends a real RFC 1035 UDP DNS packet to the local mock DNS listener.
func (s *MockOASTServer) SimulateDNSQuery(tokenOrDomain string, qtype dnsmessage.Type) (*dnsmessage.Message, error) {
	queryName := tokenOrDomain
	if !strings.HasSuffix(queryName, ".") {
		if !strings.Contains(queryName, ".") {
			queryName = fmt.Sprintf("probe-%s.%s.", tokenOrDomain, s.Domain)
		} else {
			queryName += "."
		}
	}

	qName, err := dnsmessage.NewName(queryName)
	if err != nil {
		return nil, fmt.Errorf("invalid DNS query name %q: %w", queryName, err)
	}

	reqMsg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               0x4422,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  qName,
				Type:  qtype,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	packed, err := reqMsg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS query: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, s.DNSAddr)
	if err != nil {
		return nil, fmt.Errorf("dial DNS listener %s: %w", s.DNSAddr, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(packed); err != nil {
		return nil, fmt.Errorf("write DNS query: %w", err)
	}

	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil, fmt.Errorf("read DNS response: %w", err)
	}

	var respMsg dnsmessage.Message
	if err := respMsg.Unpack(respBuf[:n]); err != nil {
		return nil, fmt.Errorf("unpack DNS response: %w", err)
	}

	return &respMsg, nil
}

// SimulateHTTPGet performs an HTTP GET request to the mock listener with token passed via path or query.
func (s *MockOASTServer) SimulateHTTPGet(token string, path string) (*http.Response, []byte, error) {
	var reqURL string
	if path != "" {
		if strings.HasPrefix(path, "/") {
			reqURL = s.HTTPURL + path
		} else {
			reqURL = s.HTTPURL + "/" + path
		}
	} else {
		reqURL = fmt.Sprintf("%s/c/%s", s.HTTPURL, token)
	}

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Host = fmt.Sprintf("probe-%s.%s", token, s.Domain)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	return resp, body, err
}

// SimulateHTTPPost performs an HTTP POST request to the mock listener with payload body.
func (s *MockOASTServer) SimulateHTTPPost(token string, path string, body []byte) (*http.Response, []byte, error) {
	var reqURL string
	if path != "" {
		if strings.HasPrefix(path, "/") {
			reqURL = s.HTTPURL + path
		} else {
			reqURL = s.HTTPURL + "/" + path
		}
	} else {
		reqURL = fmt.Sprintf("%s/c/%s", s.HTTPURL, token)
	}

	req, err := http.NewRequest(http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Host = fmt.Sprintf("probe-%s.%s", token, s.Domain)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	return resp, respBody, err
}

// WaitForCallback waits up to timeout for an interaction on the registered probe token.
func (s *MockOASTServer) WaitForCallback(token string, timeout time.Duration) (*oast.Interaction, error) {
	return s.Correlator.WaitForInteraction(context.Background(), token, timeout)
}

// PruneExpired purges expired probes that have no verified interaction evidence.
func (s *MockOASTServer) PruneExpired() int {
	return s.Listener.PruneExpired()
}

// Close terminates the mock listener and releases all allocated ports.
func (s *MockOASTServer) Close() error {
	return s.Listener.Stop()
}
