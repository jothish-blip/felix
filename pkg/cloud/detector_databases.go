package cloud

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// Database URI regexes for passive discovery
	esURLRegex       = regexp.MustCompile(`https?://([a-zA-Z0-9_\.\-]+):9200`)
	mongoURIRegex    = regexp.MustCompile(`mongodb(?:\+srv)?://(?:[^:]+:[^@]+@)?([a-zA-Z0-9_\.\-]+)(?::(\d+))?`)
	redisURIRegex    = regexp.MustCompile(`rediss?://(?:[^:]+:[^@]+@)?([a-zA-Z0-9_\.\-]+)(?::(\d+))?`)
	postgresURIRegex = regexp.MustCompile(`postgres(?:ql)?://(?:[^:]+:[^@]+@)?([a-zA-Z0-9_\.\-]+)(?::(\d+))?`)
	mysqlURIRegex    = regexp.MustCompile(`mysql://(?:[^:]+:[^@]+@)?([a-zA-Z0-9_\.\-]+)(?::(\d+))?`)
)

// ExtractDatabaseTargets parses passive content and URLs for database indicators.
func ExtractDatabaseTargets(source string, content []byte) []DiscoveredService {
	var results []DiscoveredService
	text := string(content)
	now := time.Now().UTC()

	// 1. Elasticsearch URL: :9200
	for _, match := range esURLRegex.FindAllStringSubmatch(text, -1) {
		fullURL := match[0]
		host := match[1]
		results = append(results, DiscoveredService{
			Technology:      TechElasticsearch,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomePossible,
			Confidence:      ConfidenceMedium,
			Endpoint:        fullURL,
			Host:            host,
			Port:            9200,
			Protocol:        "http",
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Discovered Elasticsearch HTTP reference in %s: %s", source, fullURL),
			SourceAsset:     source,
			DiscoveredAt:    now,
		})
	}

	// 2. MongoDB URI
	for _, match := range mongoURIRegex.FindAllStringSubmatch(text, -1) {
		host := match[1]
		port := 27017
		if len(match) > 2 && match[2] != "" {
			if p, err := strconv.Atoi(match[2]); err == nil {
				port = p
			}
		}
		results = append(results, DiscoveredService{
			Technology:      TechMongoDB,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomePossible,
			Confidence:      ConfidenceMedium,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Discovered MongoDB URI in %s targeting %s:%d", source, host, port),
			SourceAsset:     source,
			DiscoveredAt:    now,
		})
	}

	// 3. Redis URI
	for _, match := range redisURIRegex.FindAllStringSubmatch(text, -1) {
		host := match[1]
		port := 6379
		if len(match) > 2 && match[2] != "" {
			if p, err := strconv.Atoi(match[2]); err == nil {
				port = p
			}
		}
		results = append(results, DiscoveredService{
			Technology:      TechRedis,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomePossible,
			Confidence:      ConfidenceMedium,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Discovered Redis URI in %s targeting %s:%d", source, host, port),
			SourceAsset:     source,
			DiscoveredAt:    now,
		})
	}

	// 4. PostgreSQL URI
	for _, match := range postgresURIRegex.FindAllStringSubmatch(text, -1) {
		host := match[1]
		port := 5432
		if len(match) > 2 && match[2] != "" {
			if p, err := strconv.Atoi(match[2]); err == nil {
				port = p
			}
		}
		results = append(results, DiscoveredService{
			Technology:      TechPostgreSQL,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomePossible,
			Confidence:      ConfidenceMedium,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Discovered PostgreSQL URI in %s targeting %s:%d", source, host, port),
			SourceAsset:     source,
			DiscoveredAt:    now,
		})
	}

	// 5. MySQL URI
	for _, match := range mysqlURIRegex.FindAllStringSubmatch(text, -1) {
		host := match[1]
		port := 3306
		if len(match) > 2 && match[2] != "" {
			if p, err := strconv.Atoi(match[2]); err == nil {
				port = p
			}
		}
		results = append(results, DiscoveredService{
			Technology:      TechMySQL,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomePossible,
			Confidence:      ConfidenceMedium,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "PASSIVE_ANALYSIS",
			Evidence:        fmt.Sprintf("Discovered MySQL URI in %s targeting %s:%d", source, host, port),
			SourceAsset:     source,
			DiscoveredAt:    now,
		})
	}

	return results
}

// ProbeElasticsearch executes safe HTTP verification against an Elasticsearch candidate endpoint.
func ProbeElasticsearch(ctx context.Context, client *Client, targetURL string) DiscoveredService {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return DiscoveredService{
			Technology:   TechElasticsearch,
			Family:       FamilyDirectDatabase,
			Outcome:      OutcomeError,
			Endpoint:     targetURL,
			Limitations:  fmt.Sprintf("invalid URL: %v", err),
			DiscoveredAt: time.Now().UTC(),
		}
	}

	rootURL := fmt.Sprintf("%s://%s/", parsed.Scheme, parsed.Host)
	req, err := http.NewRequestWithContext(ctx, "GET", rootURL, nil)
	if err != nil {
		return DiscoveredService{
			Technology:   TechElasticsearch,
			Family:       FamilyDirectDatabase,
			Outcome:      OutcomeError,
			Endpoint:     targetURL,
			Limitations:  err.Error(),
			DiscoveredAt: time.Now().UTC(),
		}
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(ctx, req)
	if err != nil {
		return DiscoveredService{
			Technology:      TechElasticsearch,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomeInconclusive,
			Endpoint:        targetURL,
			Host:            parsed.Hostname(),
			Port:            9200,
			Protocol:        parsed.Scheme,
			DetectionMethod: "HTTP_PROBE",
			Limitations:     fmt.Sprintf("probe connection error: %v", err),
			DiscoveredAt:    time.Now().UTC(),
		}
	}

	bodyStr := string(resp.Body)
	elasticHeader := resp.Header.Get("X-elastic-product")

	// 1. Unauthenticated or Open Elasticsearch Root
	if resp.StatusCode == http.StatusOK {
		var esInfo struct {
			Name        string `json:"name"`
			ClusterName string `json:"cluster_name"`
			Tagline     string `json:"tagline"`
			Version     struct {
				Number string `json:"number"`
			} `json:"version"`
		}
		if json.Unmarshal(resp.Body, &esInfo) == nil {
			if strings.EqualFold(esInfo.Tagline, "You Know, for Search") || esInfo.ClusterName != "" || elasticHeader == "Elasticsearch" {
				return DiscoveredService{
					Technology:      TechElasticsearch,
					Family:          FamilyDirectDatabase,
					Outcome:         OutcomeDetected,
					Confidence:      ConfidenceHigh,
					Endpoint:        rootURL,
					Host:            parsed.Hostname(),
					Port:            9200,
					Protocol:        parsed.Scheme,
					DetectionMethod: "HTTP_PROBE",
					Version:         esInfo.Version.Number,
					AuthRequired:    false,
					PublicAccess:    false,
					Evidence:        fmt.Sprintf("Elasticsearch root responded 200 OK. Tagline: %q, Cluster: %q, Version: %q", esInfo.Tagline, esInfo.ClusterName, esInfo.Version.Number),
					Limitations:     "Root cluster info confirms Elasticsearch presence; indices read permissions require Phase 2.2 verification",
					Metadata: map[string]any{
						"cluster_name": esInfo.ClusterName,
						"node_name":    esInfo.Name,
						"version":      esInfo.Version.Number,
						"tagline":      esInfo.Tagline,
					},
					InScope:      true,
					DiscoveredAt: time.Now().UTC(),
				}
			}
		}
	}

	// 2. Authenticated Elasticsearch Instance (HTTP 401)
	if resp.StatusCode == http.StatusUnauthorized {
		authHdr := resp.Header.Get("WWW-Authenticate")
		isElasticAuth := strings.Contains(strings.ToLower(authHdr), "security") ||
			strings.Contains(bodyStr, "security_exception") ||
			strings.EqualFold(elasticHeader, "Elasticsearch")

		if isElasticAuth {
			return DiscoveredService{
				Technology:      TechElasticsearch,
				Family:          FamilyDirectDatabase,
				Outcome:         OutcomeDetected,
				Confidence:      ConfidenceHigh,
				Endpoint:        rootURL,
				Host:            parsed.Hostname(),
				Port:            9200,
				Protocol:        parsed.Scheme,
				DetectionMethod: "HTTP_PROBE",
				AuthRequired:    true,
				PublicAccess:    false,
				Evidence:        "Elasticsearch security active: HTTP 401 security_exception authentication challenge received",
				Metadata: map[string]any{
					"auth_realm": authHdr,
				},
				InScope:      true,
				DiscoveredAt: time.Now().UTC(),
			}
		}
	}

	return DiscoveredService{
		Technology:      TechElasticsearch,
		Family:          FamilyDirectDatabase,
		Outcome:         OutcomeNotDetected,
		Endpoint:        targetURL,
		Host:            parsed.Hostname(),
		DetectionMethod: "HTTP_PROBE",
		Evidence:        fmt.Sprintf("HTTP status %d received without Elasticsearch signatures", resp.StatusCode),
		DiscoveredAt:    time.Now().UTC(),
	}
}

// ProbeMongoDB executes safe TCP/HTTP verification against a MongoDB target.
func ProbeMongoDB(ctx context.Context, client *Client, host string, port int) DiscoveredService {
	if port <= 0 {
		port = 27017
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	now := time.Now().UTC()

	checkHTTP := func() (DiscoveredService, bool) {
		httpURL := fmt.Sprintf("http://%s/", addr)
		req, err := http.NewRequestWithContext(ctx, "GET", httpURL, nil)
		if err == nil {
			if resp, err := client.Do(ctx, req); err == nil {
				body := string(resp.Body)
				if strings.Contains(body, "trying to access MongoDB over HTTP on the native driver port") {
					return DiscoveredService{
						Technology:      TechMongoDB,
						Family:          FamilyDirectDatabase,
						Outcome:         OutcomeDetected,
						Confidence:      ConfidenceHigh,
						Endpoint:        addr,
						Host:            host,
						Port:            port,
						Protocol:        "tcp",
						DetectionMethod: "HTTP_PROBE",
						AuthRequired:    true,
						Evidence:        "MongoDB native driver notice observed on HTTP endpoint: 'trying to access MongoDB over HTTP on the native driver port'",
						InScope:         true,
						DiscoveredAt:    now,
					}, true
				}
			}
		}
		return DiscoveredService{}, false
	}

	// Step A: Check for MongoDB HTTP native driver response
	if ds, ok := checkHTTP(); ok {
		return ds
	}

	// Step B: Safe TCP handshake probe on MongoDB wire protocol
	conn, err := client.SafeDialContext(ctx, "tcp", addr)
	if err != nil {
		return DiscoveredService{
			Technology:      TechMongoDB,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomeInconclusive,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "TCP_PROBE",
			Limitations:     fmt.Sprintf("connection refused or blocked: %v", err),
			DiscoveredAt:    now,
		}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	// Construct safe BSON isMaster query (OP_QUERY opcode 2004)
	// BSON document: \x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00
	bsonDoc := []byte{
		0x13, 0x00, 0x00, 0x00, // doc len: 19 bytes
		0x10,                               // type int32
		'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0x00, // "isMaster"
		0x01, 0x00, 0x00, 0x00, // value: 1
		0x00, // doc terminator
	}

	// OP_QUERY packet:
	// MsgHeader: messageLength (int32), requestID (int32), responseTo (int32), opCode (int32 = 2004)
	// flags (int32 = 0), fullCollectionName ("admin.$cmd\x00"), numberToSkip (0), numberToReturn (1), query (BSON)
	collName := []byte("admin.$cmd\x00")
	totalLen := int32(16 + 4 + len(collName) + 4 + 4 + len(bsonDoc))

	var pkt bytes.Buffer
	_ = binary.Write(&pkt, binary.LittleEndian, totalLen)
	_ = binary.Write(&pkt, binary.LittleEndian, int32(1001)) // requestID
	_ = binary.Write(&pkt, binary.LittleEndian, int32(0))    // responseTo
	_ = binary.Write(&pkt, binary.LittleEndian, int32(2004)) // OP_QUERY
	_ = binary.Write(&pkt, binary.LittleEndian, int32(0))    // flags
	pkt.Write(collName)
	_ = binary.Write(&pkt, binary.LittleEndian, int32(0)) // numberToSkip
	_ = binary.Write(&pkt, binary.LittleEndian, int32(1)) // numberToReturn
	pkt.Write(bsonDoc)

	if _, err := conn.Write(pkt.Bytes()); err != nil {
		return DiscoveredService{
			Technology:      TechMongoDB,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomeInconclusive,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "TCP_PROBE",
			Limitations:     fmt.Sprintf("write error: %v", err),
			DiscoveredAt:    now,
		}
	}

	respBuf := make([]byte, 1024)
	n, err := conn.Read(respBuf)
	if err != nil || n < 16 {
		return DiscoveredService{
			Technology:      TechMongoDB,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomeInconclusive,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "TCP_PROBE",
			Limitations:     fmt.Sprintf("read error or insufficient header bytes: %v", err),
			DiscoveredAt:    now,
		}
	}

	respBytes := respBuf[:n]
	respStr := string(respBytes)

	// MongoDB Wire Protocol responses contain recognizable BSON markers:
	// "ismaster", "isWritablePrimary", "maxBsonObjectSize", "requires authentication"
	if strings.Contains(respStr, "ismaster") ||
		strings.Contains(respStr, "isWritablePrimary") ||
		strings.Contains(respStr, "maxBsonObjectSize") ||
		strings.Contains(respStr, "topologyVersion") {
		authRequired := strings.Contains(respStr, "requires authentication") || strings.Contains(respStr, "Unauthorized")
		return DiscoveredService{
			Technology:      TechMongoDB,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "TCP_PROBE",
			AuthRequired:    authRequired,
			PublicAccess:    false,
			Evidence:        "MongoDB wire protocol response confirmed via BSON isMaster handshake",
			Limitations:     "isMaster handshake confirms active MongoDB wire protocol; database authentication and collection read permissions require Phase 2.2 verification",
			InScope:         true,
			DiscoveredAt:    now,
		}
	}

	if strings.Contains(respStr, "requires authentication") || strings.Contains(respStr, "command isMaster requires authentication") {
		return DiscoveredService{
			Technology:      TechMongoDB,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "TCP_PROBE",
			AuthRequired:    true,
			PublicAccess:    false,
			Evidence:        "MongoDB instance identified: server returned authentication requirement error",
			InScope:         true,
			DiscoveredAt:    now,
		}
	}

	return DiscoveredService{
		Technology:      TechMongoDB,
		Family:          FamilyDirectDatabase,
		Outcome:         OutcomeNotDetected,
		Host:            host,
		Port:            port,
		DetectionMethod: "TCP_PROBE",
		Evidence:        "No MongoDB BSON markers returned from port",
		DiscoveredAt:    now,
	}
}

// ProbeRedis executes safe verification against a candidate Redis server via safe TCP probe.
func ProbeRedis(ctx context.Context, client *Client, host string, port int) DiscoveredService {
	if port <= 0 {
		port = 6379
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	now := time.Now().UTC()

	conn, err := client.SafeDialContext(ctx, "tcp", addr)
	if err != nil {
		return DiscoveredService{
			Technology:      TechRedis,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomeInconclusive,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "TCP_PROBE",
			Limitations:     fmt.Sprintf("connection error: %v", err),
			DiscoveredAt:    now,
		}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	// Send safe Redis PING command
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return DiscoveredService{
			Technology:      TechRedis,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomeInconclusive,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "TCP_PROBE",
			Limitations:     fmt.Sprintf("failed to send PING: %v", err),
			DiscoveredAt:    now,
		}
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return DiscoveredService{
			Technology:      TechRedis,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomeInconclusive,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "TCP_PROBE",
			Limitations:     fmt.Sprintf("failed to read response: %v", err),
			DiscoveredAt:    now,
		}
	}

	reply := string(buf[:n])

	// 1. Unauthenticated Redis (+PONG)
	if strings.HasPrefix(reply, "+PONG") {
		return DiscoveredService{
			Technology:      TechRedis,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "TCP_PROBE",
			AuthRequired:    false,
			PublicAccess:    false,
			Evidence:        "Redis responded '+PONG' to PING command without requiring authentication",
			Limitations:     "PING response confirms active Redis protocol; keyspace access and data read permissions require Phase 2.2 verification",
			InScope:         true,
			DiscoveredAt:    now,
		}
	}

	// 2. Authenticated Redis (-NOAUTH Authentication required)
	if strings.HasPrefix(reply, "-NOAUTH") || strings.Contains(reply, "Authentication required") {
		return DiscoveredService{
			Technology:      TechRedis,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "TCP_PROBE",
			AuthRequired:    true,
			PublicAccess:    false,
			Evidence:        fmt.Sprintf("Redis instance confirmed: %s", strings.TrimSpace(reply)),
			InScope:         true,
			DiscoveredAt:    now,
		}
	}

	// 3. Protected Mode Redis (-DENIED)
	if strings.HasPrefix(reply, "-DENIED") || strings.Contains(reply, "protected mode") {
		return DiscoveredService{
			Technology:      TechRedis,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomeDetected,
			Confidence:      ConfidenceHigh,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "TCP_PROBE",
			AuthRequired:    true,
			PublicAccess:    false,
			Evidence:        "Redis protected mode active; connection rejected as unauthorized",
			InScope:         true,
			DiscoveredAt:    now,
		}
	}

	return DiscoveredService{
		Technology:      TechRedis,
		Family:          FamilyDirectDatabase,
		Outcome:         OutcomeNotDetected,
		Host:            host,
		Port:            port,
		DetectionMethod: "TCP_PROBE",
		Evidence:        fmt.Sprintf("Non-Redis response received: %q", strings.TrimSpace(reply)),
		DiscoveredAt:    now,
	}
}

// ProbePostgreSQL executes safe protocol verification against a PostgreSQL service.
func ProbePostgreSQL(ctx context.Context, client *Client, host string, port int) DiscoveredService {
	if port <= 0 {
		port = 5432
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	now := time.Now().UTC()

	conn, err := client.SafeDialContext(ctx, "tcp", addr)
	if err != nil {
		return DiscoveredService{
			Technology:      TechPostgreSQL,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomeInconclusive,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "TCP_PROBE",
			Limitations:     fmt.Sprintf("connection error: %v", err),
			DiscoveredAt:    now,
		}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	// Send standard PostgreSQL SSLRequest packet:
	// Length (int32 = 8), Magic Code (int32 = 80877103 = 0x04D2162F)
	sslReq := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	if _, err := conn.Write(sslReq); err != nil {
		return DiscoveredService{
			Technology:      TechPostgreSQL,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomeInconclusive,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "TCP_PROBE",
			Limitations:     fmt.Sprintf("failed to write SSLRequest: %v", err),
			DiscoveredAt:    now,
		}
	}

	resp := make([]byte, 1)
	n, err := conn.Read(resp)
	if err == nil && n == 1 {
		// PostgreSQL servers return 'S' (SSL allowed) or 'N' (SSL not supported)
		if resp[0] == 'S' || resp[0] == 'N' {
			evidence := fmt.Sprintf("PostgreSQL responded '%c' to SSLRequest packet", resp[0])
			return DiscoveredService{
				Technology:      TechPostgreSQL,
				Family:          FamilyDirectDatabase,
				Outcome:         OutcomeDetected,
				Confidence:      ConfidenceHigh,
				Host:            host,
				Port:            port,
				Protocol:        "tcp",
				DetectionMethod: "TCP_PROBE",
				AuthRequired:    false,
				PublicAccess:    false,
				Evidence:        evidence,
				Limitations:     "SSL negotiation confirms PostgreSQL protocol; server authentication policy is evaluated during connection handshake in Phase 2.2",
				Metadata: map[string]any{
					"ssl_support": resp[0] == 'S',
				},
				InScope:      true,
				DiscoveredAt: now,
			}
		}
	}

	return DiscoveredService{
		Technology:      TechPostgreSQL,
		Family:          FamilyDirectDatabase,
		Outcome:         OutcomeNotDetected,
		Host:            host,
		Port:            port,
		DetectionMethod: "TCP_PROBE",
		Evidence:        "PostgreSQL SSLRequest handshake produced non-standard response",
		DiscoveredAt:    now,
	}
}

// ProbeMySQL executes safe protocol verification against a MySQL service (server-speaks-first).
func ProbeMySQL(ctx context.Context, client *Client, host string, port int) DiscoveredService {
	if port <= 0 {
		port = 3306
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	now := time.Now().UTC()

	conn, err := client.SafeDialContext(ctx, "tcp", addr)
	if err != nil {
		return DiscoveredService{
			Technology:      TechMySQL,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomeInconclusive,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "TCP_PROBE",
			Limitations:     fmt.Sprintf("connection error: %v", err),
			DiscoveredAt:    now,
		}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	// In MySQL protocol, server speaks first: Initial Handshake Packet or Error Packet
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return DiscoveredService{
			Technology:      TechMySQL,
			Family:          FamilyDirectDatabase,
			Outcome:         OutcomeInconclusive,
			Host:            host,
			Port:            port,
			Protocol:        "tcp",
			DetectionMethod: "TCP_PROBE",
			Limitations:     fmt.Sprintf("read error from initial handshake: %v", err),
			DiscoveredAt:    now,
		}
	}

	packet := buf[:n]
	// Packet format: 3 bytes payload length, 1 byte sequence id (0x00), then payload
	if len(packet) >= 5 && packet[3] == 0x00 {
		protoVersion := packet[4]

		// 1. Initial Handshake Packet (Protocol version 10 is standard for MySQL 5+, 8+, MariaDB)
		if protoVersion == 0x0A {
			// Extract null-terminated version string
			verBytes := packet[5:]
			nullIdx := bytes.IndexByte(verBytes, 0x00)
			version := "unknown"
			if nullIdx != -1 {
				version = string(verBytes[:nullIdx])
			}

			return DiscoveredService{
				Technology:      TechMySQL,
				Family:          FamilyDirectDatabase,
				Outcome:         OutcomeDetected,
				Confidence:      ConfidenceHigh,
				Host:            host,
				Port:            port,
				Protocol:        "tcp",
				DetectionMethod: "TCP_PROBE",
				Version:         version,
				AuthRequired:    false,
				PublicAccess:    false,
				Evidence:        fmt.Sprintf("MySQL Initial Handshake Packet confirmed (Protocol %d, Version %q)", protoVersion, version),
				Limitations:     "Initial Handshake Packet confirms MySQL protocol; authentication requirements and user access policies are evaluated during login phase in Phase 2.2",
				Metadata: map[string]any{
					"protocol_version": int(protoVersion),
					"server_version":   version,
				},
				InScope:      true,
				DiscoveredAt: now,
			}
		}

		// 2. MySQL Error Packet (0xFF) e.g., Host is not allowed to connect (1130) or too many connections (1040)
		if protoVersion == 0xFF {
			errCode := binary.LittleEndian.Uint16(packet[5:7])
			errMessage := string(packet[7:])
			return DiscoveredService{
				Technology:      TechMySQL,
				Family:          FamilyDirectDatabase,
				Outcome:         OutcomeDetected,
				Confidence:      ConfidenceHigh,
				Host:            host,
				Port:            port,
				Protocol:        "tcp",
				DetectionMethod: "TCP_PROBE",
				AuthRequired:    true,
				PublicAccess:    false,
				Evidence:        fmt.Sprintf("MySQL Error Packet (Code %d: %s)", errCode, strings.TrimSpace(errMessage)),
				Metadata: map[string]any{
					"error_code":    errCode,
					"error_message": strings.TrimSpace(errMessage),
				},
				InScope:      true,
				DiscoveredAt: now,
			}
		}
	}

	return DiscoveredService{
		Technology:      TechMySQL,
		Family:          FamilyDirectDatabase,
		Outcome:         OutcomeNotDetected,
		Host:            host,
		Port:            port,
		DetectionMethod: "TCP_PROBE",
		Evidence:        "Initial bytes do not match MySQL handshake structure",
		DiscoveredAt:    now,
	}
}
