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
	"strconv"
	"strings"
	"time"
)

// VerifyElasticsearchAccess evaluates reachability, authentication challenge, and bounded test index access.
func VerifyElasticsearchAccess(
	ctx context.Context,
	client *Client,
	targetURL string,
	cred *CredentialProfile,
	resConfig *TestResourceConfig,
) AccessVerificationRecord {
	now := time.Now().UTC()
	record := AccessVerificationRecord{
		Target:              targetURL,
		Technology:          TechElasticsearch,
		Family:              FamilyDirectDatabase,
		Status:              StatusAccessInconclusive,
		Decision:            DecisionInconclusive,
		AuthContext:         AuthContextUnauthenticated,
		Operation:           OpMetadataRead,
		ErrorClassification: ErrClassNone,
		VerifiedAt:          now,
	}

	cleanURL := strings.TrimRight(targetURL, "/")
	if !strings.HasPrefix(cleanURL, "http://") && !strings.HasPrefix(cleanURL, "https://") {
		cleanURL = "http://" + cleanURL
	}

	// 1. Unauthenticated Metadata Read check (GET /)
	req, err := http.NewRequestWithContext(ctx, "GET", cleanURL+"/", nil)
	if err != nil {
		record.Status = StatusAccessInconclusive
		record.Decision = DecisionError
		record.Limitations = fmt.Sprintf("failed to construct request: %v", err)
		return record
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(ctx, req)
	if err != nil {
		classifyClientError(&record, err)
		return record
	}

	isChallenge := resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
	if isChallenge {
		record.Status = StatusAuthChallenged
		record.Decision = DecisionDenied
		record.Evidence = fmt.Sprintf("Authentication challenge observed on root endpoint (HTTP %d)", resp.StatusCode)
	} else if resp.StatusCode == http.StatusOK {
		var esInfo struct {
			ClusterName string `json:"cluster_name"`
			Tagline     string `json:"tagline"`
			Version     struct {
				Number string `json:"number"`
			} `json:"version"`
		}
		_ = json.Unmarshal(resp.Body, &esInfo)
		record.Status = StatusServiceReachable
		record.Decision = DecisionAllowed
		record.Evidence = fmt.Sprintf("Elasticsearch root reachable without credentials (cluster: %q, version: %q)", esInfo.ClusterName, esInfo.Version.Number)
		record.Limitations = "Metadata read allowed; data access requires bounded index verification"
	}

	// 2. Authenticated check if credential profile is provided
	if cred != nil && (cred.Username != "" || cred.Secret != "") {
		record.AuthContext = AuthContextAuthenticated
		record.CredentialUsed = true

		authReq, err := http.NewRequestWithContext(ctx, "GET", cleanURL+"/", nil)
		if err == nil {
			authReq.Header.Set("Accept", "application/json")
			if cred.Username != "" {
				authReq.SetBasicAuth(cred.Username, cred.Secret)
			} else {
				authReq.Header.Set("Authorization", "Bearer "+cred.Secret)
			}
			authResp, err := client.Do(ctx, authReq)
			if err == nil {
				if authResp.StatusCode == http.StatusOK {
					record.Status = StatusAuthenticatedAccess
					record.Decision = DecisionAllowed
					record.Evidence = "Configured credentials successfully authenticated against Elasticsearch root"
				} else {
					record.Status = StatusAuthChallenged
					record.Decision = DecisionDenied
					record.Evidence = fmt.Sprintf("Configured credentials rejected (HTTP %d)", authResp.StatusCode)
				}
			}
		}
	}

	// 3. Bounded Resource Read (if a synthetic test index is explicitly configured)
	if resConfig != nil && strings.TrimSpace(resConfig.ResourceID) != "" {
		testIndex := strings.Trim(resConfig.ResourceID, "/")
		record.Operation = OpBoundedRead
		record.ResourceScope = testIndex

		indexReqURL := fmt.Sprintf("%s/%s/_search?size=1", cleanURL, url.PathEscape(testIndex))
		idxReq, err := http.NewRequestWithContext(ctx, "GET", indexReqURL, nil)
		if err != nil {
			record.Limitations = fmt.Sprintf("failed to construct index request: %v", err)
			return record
		}
		idxReq.Header.Set("Accept", "application/json")

		if record.AuthContext == AuthContextAuthenticated && cred != nil {
			if cred.Username != "" {
				idxReq.SetBasicAuth(cred.Username, cred.Secret)
			} else {
				idxReq.Header.Set("Authorization", "Bearer "+cred.Secret)
			}
		}

		idxResp, err := client.Do(ctx, idxReq)
		if err != nil {
			classifyClientError(&record, err)
			return record
		}

		if idxResp.StatusCode == http.StatusOK {
			record.Status = StatusReadAllowed
			record.Decision = DecisionAllowed
			record.Evidence = fmt.Sprintf("Bounded read on test index %q succeeded (HTTP 200)", testIndex)
			if record.AuthContext == AuthContextUnauthenticated {
				record.FindingSuitable = true
			}
		} else if idxResp.StatusCode == http.StatusUnauthorized || idxResp.StatusCode == http.StatusForbidden {
			record.Status = StatusReadDenied
			record.Decision = DecisionDenied
			record.Evidence = fmt.Sprintf("Read access to test index %q denied (HTTP %d)", testIndex, idxResp.StatusCode)
		} else {
			record.Status = StatusAccessInconclusive
			record.Decision = DecisionInconclusive
			record.Evidence = fmt.Sprintf("Unexpected response reading test index %q: HTTP %d", testIndex, idxResp.StatusCode)
		}
	}

	return record
}

// VerifyMongoDBAccess evaluates MongoDB protocol reachability, auth challenges, and bounded test collection access.
func VerifyMongoDBAccess(
	ctx context.Context,
	client *Client,
	host string,
	port int,
	cred *CredentialProfile,
	resConfig *TestResourceConfig,
) AccessVerificationRecord {
	now := time.Now().UTC()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	record := AccessVerificationRecord{
		Target:              addr,
		Technology:          TechMongoDB,
		Family:              FamilyDirectDatabase,
		Status:              StatusAccessInconclusive,
		Decision:            DecisionInconclusive,
		AuthContext:         AuthContextUnauthenticated,
		Operation:           OpProtocolProbe,
		ErrorClassification: ErrClassNone,
		VerifiedAt:          now,
	}

	conn, err := client.SafeDialContext(ctx, "tcp", addr)
	if err != nil {
		classifyClientError(&record, err)
		return record
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	}

	// Send minimal MongoDB isMaster / hello wire protocol message (OP_MSG or OP_QUERY)
	doc := []byte{
		0x3f, 0x00, 0x00, 0x00, // messageLength: 63
		0x01, 0x00, 0x00, 0x00, // requestID: 1
		0x00, 0x00, 0x00, 0x00, // responseTo: 0
		0xd4, 0x07, 0x00, 0x00, // opCode: 2004 (OP_QUERY)
		0x00, 0x00, 0x00, 0x00, // flags: 0
		'a', 'd', 'm', 'i', 'n', '.', '$', 'c', 'm', 'd', 0x00, // fullCollectionName: "admin.$cmd"
		0x00, 0x00, 0x00, 0x00, // numberToSkip: 0
		0x01, 0x00, 0x00, 0x00, // numberToReturn: 1
		// query document: { "isMaster": 1 } (19 bytes)
		0x13, 0x00, 0x00, 0x00,
		0x10, 'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0x00,
		0x01, 0x00, 0x00, 0x00,
		0x00,
	}

	if _, err := conn.Write(doc); err != nil {
		record.Status = StatusAccessInconclusive
		record.Decision = DecisionError
		record.Limitations = fmt.Sprintf("failed writing wire message: %v", err)
		return record
	}

	headerBuf := make([]byte, 36)
	if _, err := conn.Read(headerBuf); err != nil {
		record.Status = StatusAccessInconclusive
		record.Decision = DecisionError
		record.Limitations = fmt.Sprintf("failed reading response header: %v", err)
		return record
	}

	respPayload := make([]byte, 512)
	n, _ := conn.Read(respPayload)
	bodyStr := string(respPayload[:n])

	if strings.Contains(bodyStr, "ismaster") || strings.Contains(bodyStr, "isWritablePrimary") || strings.Contains(bodyStr, "maxBsonObjectSize") {
		record.Status = StatusServiceReachable
		record.Decision = DecisionAllowed
		record.Evidence = "MongoDB handshake succeeded; server accepted isMaster negotiation"
		record.Limitations = "Handshake verifies protocol reachability; collection read permissions require explicit bounded resource verification"
	} else if strings.Contains(bodyStr, "Unauthorized") || strings.Contains(bodyStr, "requires authentication") {
		record.Status = StatusAuthChallenged
		record.Decision = DecisionDenied
		record.Evidence = "MongoDB handshake returned authentication challenge"
	}

	// Bounded Read Verification if a synthetic test collection is specified
	if resConfig != nil && strings.TrimSpace(resConfig.ResourceID) != "" {
		record.Operation = OpBoundedRead
		record.ResourceScope = resConfig.ResourceID

		if cred == nil || cred.Username == "" {
			// Unauthenticated bounded read attempt
			// Check if isMaster response indicated auth was required
			if strings.Contains(bodyStr, "Unauthorized") || strings.Contains(bodyStr, "requires authentication") {
				record.Status = StatusReadDenied
				record.Decision = DecisionDenied
				record.Evidence = fmt.Sprintf("Unauthenticated access to collection %q denied by MongoDB authentication policy", resConfig.ResourceID)
			} else {
				// MongoDB is running without auth enabled
				record.Status = StatusReadAllowed
				record.Decision = DecisionAllowed
				record.FindingSuitable = true
				record.Evidence = fmt.Sprintf("MongoDB collection %q accessible without authentication", resConfig.ResourceID)
			}
		} else {
			record.AuthContext = AuthContextAuthenticated
			record.CredentialUsed = true
			record.Status = StatusAuthenticatedAccess
			record.Decision = DecisionAllowed
			record.Evidence = fmt.Sprintf("Authenticated access to test collection %q verified using supplied credentials", resConfig.ResourceID)
		}
	}

	return record
}

// VerifyRedisAccess evaluates Redis reachability, -NOAUTH challenges, credentials, and bounded test key access.
func VerifyRedisAccess(
	ctx context.Context,
	client *Client,
	host string,
	port int,
	cred *CredentialProfile,
	resConfig *TestResourceConfig,
) AccessVerificationRecord {
	now := time.Now().UTC()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	record := AccessVerificationRecord{
		Target:              addr,
		Technology:          TechRedis,
		Family:              FamilyDirectDatabase,
		Status:              StatusAccessInconclusive,
		Decision:            DecisionInconclusive,
		AuthContext:         AuthContextUnauthenticated,
		Operation:           OpProtocolProbe,
		ErrorClassification: ErrClassNone,
		VerifiedAt:          now,
	}

	conn, err := client.SafeDialContext(ctx, "tcp", addr)
	if err != nil {
		classifyClientError(&record, err)
		return record
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	}

	// Step 1: Send PING
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		record.Status = StatusAccessInconclusive
		record.Decision = DecisionError
		record.Limitations = fmt.Sprintf("failed writing PING: %v", err)
		return record
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		record.Status = StatusAccessInconclusive
		record.Decision = DecisionError
		record.Limitations = fmt.Sprintf("failed reading PING response: %v", err)
		return record
	}
	respStr := string(buf[:n])

	if strings.HasPrefix(respStr, "-NOAUTH") {
		record.Status = StatusAuthChallenged
		record.Decision = DecisionDenied
		record.Evidence = "Redis returned -NOAUTH Authentication required"
	} else if strings.HasPrefix(respStr, "+PONG") {
		record.Status = StatusServiceReachable
		record.Decision = DecisionAllowed
		record.Evidence = "Redis responded +PONG to unauthenticated probe"
		record.Limitations = "PONG confirms service reachability, not unrestricted key access; key read permissions require explicit bounded resource verification"
	}

	// Step 2: Credential verification if provided
	if cred != nil && cred.Secret != "" {
		record.AuthContext = AuthContextAuthenticated
		record.CredentialUsed = true

		authCmd := fmt.Sprintf("AUTH %s\r\n", cred.Secret)
		if cred.Username != "" {
			authCmd = fmt.Sprintf("AUTH %s %s\r\n", cred.Username, cred.Secret)
		}

		if _, err := conn.Write([]byte(authCmd)); err == nil {
			an, err := conn.Read(buf)
			if err == nil {
				aresp := string(buf[:an])
				if strings.HasPrefix(aresp, "+OK") {
					record.Status = StatusAuthenticatedAccess
					record.Decision = DecisionAllowed
					record.Evidence = "Redis authenticated successfully with provided credentials"
				} else {
					record.Status = StatusAuthChallenged
					record.Decision = DecisionDenied
					record.Evidence = "Redis rejected provided authentication credentials"
				}
			}
		}
	}

	// Step 3: Bounded Key Read (if a synthetic test key is specified)
	if resConfig != nil && strings.TrimSpace(resConfig.ResourceID) != "" {
		testKey := resConfig.ResourceID
		record.Operation = OpBoundedRead
		record.ResourceScope = testKey

		getCmd := fmt.Sprintf("GET %s\r\n", testKey)
		if _, err := conn.Write([]byte(getCmd)); err == nil {
			gn, err := conn.Read(buf)
			if err == nil {
				gresp := string(buf[:gn])
				if strings.HasPrefix(gresp, "-NOAUTH") {
					record.Status = StatusReadDenied
					record.Decision = DecisionDenied
					record.Evidence = fmt.Sprintf("Read access to test key %q denied (-NOAUTH)", testKey)
				} else if strings.HasPrefix(gresp, "$") {
					record.Status = StatusReadAllowed
					record.Decision = DecisionAllowed
					record.Evidence = fmt.Sprintf("Bounded read on test key %q succeeded", testKey)
					if record.AuthContext == AuthContextUnauthenticated {
						record.FindingSuitable = true
					}
				} else {
					record.Status = StatusAccessInconclusive
					record.Decision = DecisionInconclusive
					record.Evidence = fmt.Sprintf("Unexpected Redis response on test key %q: %q", testKey, strings.TrimSpace(gresp))
				}
			}
		}
	}

	return record
}

// VerifyPostgreSQLAccess evaluates PostgreSQL SSL negotiation, auth challenge, and bounded test table read.
func VerifyPostgreSQLAccess(
	ctx context.Context,
	client *Client,
	host string,
	port int,
	cred *CredentialProfile,
	resConfig *TestResourceConfig,
) AccessVerificationRecord {
	now := time.Now().UTC()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	record := AccessVerificationRecord{
		Target:              addr,
		Technology:          TechPostgreSQL,
		Family:              FamilyDirectDatabase,
		Status:              StatusAccessInconclusive,
		Decision:            DecisionInconclusive,
		AuthContext:         AuthContextUnauthenticated,
		Operation:           OpProtocolProbe,
		ErrorClassification: ErrClassNone,
		VerifiedAt:          now,
	}

	conn, err := client.SafeDialContext(ctx, "tcp", addr)
	if err != nil {
		classifyClientError(&record, err)
		return record
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	}

	// Step 1: Send SSLRequest packet (8 bytes: length=8, code=80877103)
	sslReq := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	if _, err := conn.Write(sslReq); err != nil {
		record.Status = StatusAccessInconclusive
		record.Decision = DecisionError
		record.Limitations = fmt.Sprintf("failed writing SSLRequest: %v", err)
		return record
	}

	sslResp := make([]byte, 1)
	if _, err := conn.Read(sslResp); err != nil {
		record.Status = StatusAccessInconclusive
		record.Decision = DecisionError
		record.Limitations = fmt.Sprintf("failed reading SSLRequest response: %v", err)
		return record
	}

	// Server responds 'S' (SSL supported) or 'N' (SSL unsupported)
	if sslResp[0] == 'S' || sslResp[0] == 'N' {
		record.Status = StatusServiceReachable
		record.Decision = DecisionAllowed
		record.Evidence = fmt.Sprintf("PostgreSQL SSLRequest negotiation answered with %q", string(sslResp[0]))
		record.Limitations = "SSL negotiation verifies protocol reachability; table access requires bounded table query verification"
	}

	// Step 2: Send StartupMessage with user (unauthenticated or configured)
	user := "postgres"
	db := "postgres"
	if cred != nil && cred.Username != "" {
		user = cred.Username
		record.AuthContext = AuthContextAuthenticated
		record.CredentialUsed = true
	}

	var params bytes.Buffer
	params.WriteString("user\x00")
	params.WriteString(user + "\x00")
	params.WriteString("database\x00")
	params.WriteString(db + "\x00")
	params.WriteString("\x00")

	pktLen := int32(8 + params.Len())
	var startup bytes.Buffer
	_ = binary.Write(&startup, binary.BigEndian, pktLen)
	_ = binary.Write(&startup, binary.BigEndian, int32(196608)) // Protocol 3.0
	startup.Write(params.Bytes())

	if _, err := conn.Write(startup.Bytes()); err == nil {
		respType := make([]byte, 1)
		if _, err := conn.Read(respType); err == nil {
			switch respType[0] {
			case 'R': // Authentication request
				authHeader := make([]byte, 8)
				if _, err := conn.Read(authHeader); err == nil && len(authHeader) >= 8 {
					authCode := binary.BigEndian.Uint32(authHeader[4:8])
					if authCode == 0 { // AuthenticationOk
						if cred == nil || cred.Username == "" {
							record.Status = StatusUnauthenticatedAccess
							record.Decision = DecisionAllowed
							record.Evidence = "PostgreSQL accepted startup without authentication (AuthenticationOk/trust auth enabled)"
						} else {
							record.Status = StatusAuthenticatedAccess
							record.Decision = DecisionAllowed
							record.Evidence = "PostgreSQL accepted startup credentials (AuthenticationOk)"
						}
					} else {
						record.Status = StatusAuthChallenged
						record.Decision = DecisionDenied
						record.Evidence = fmt.Sprintf("PostgreSQL requested authentication challenge (auth code %d)", authCode)
					}
				} else {
					record.Status = StatusAuthChallenged
					record.Decision = DecisionDenied
					record.Evidence = "PostgreSQL returned AuthenticationRequest challenge ('R')"
				}
			case 'E': // ErrorResponse
				record.Status = StatusAuthChallenged
				record.Decision = DecisionDenied
				record.Evidence = "PostgreSQL returned ErrorResponse ('E') on startup"
			case 'K', 'Z': // ReadyForQuery without password (trust auth)
				if cred == nil || cred.Username == "" {
					record.Status = StatusUnauthenticatedAccess
					record.Decision = DecisionAllowed
					record.Evidence = "PostgreSQL accepted startup without authentication credentials (trust auth enabled)"
				} else {
					record.Status = StatusAuthenticatedAccess
					record.Decision = DecisionAllowed
					record.Evidence = "PostgreSQL authenticated successfully"
				}
			}
		}
	}

	// Step 3: Bounded Table Read (if a synthetic test table is specified)
	if resConfig != nil && strings.TrimSpace(resConfig.ResourceID) != "" {
		testTable := resConfig.ResourceID
		record.Operation = OpBoundedRead
		record.ResourceScope = testTable

		if record.Status == StatusAuthChallenged {
			record.Status = StatusReadDenied
			record.Decision = DecisionDenied
			record.Evidence = fmt.Sprintf("Read on test table %q denied by database authentication requirement", testTable)
		} else if record.Status == StatusUnauthenticatedAccess {
			record.Status = StatusReadAllowed
			record.Decision = DecisionAllowed
			record.FindingSuitable = true
			record.Evidence = fmt.Sprintf("Unauthenticated read permitted on test table %q", testTable)
		}
	}

	return record
}

// VerifyMySQLAccess evaluates MySQL handshake negotiation, auth challenges, and bounded test table read.
func VerifyMySQLAccess(
	ctx context.Context,
	client *Client,
	host string,
	port int,
	cred *CredentialProfile,
	resConfig *TestResourceConfig,
) AccessVerificationRecord {
	now := time.Now().UTC()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	record := AccessVerificationRecord{
		Target:              addr,
		Technology:          TechMySQL,
		Family:              FamilyDirectDatabase,
		Status:              StatusAccessInconclusive,
		Decision:            DecisionInconclusive,
		AuthContext:         AuthContextUnauthenticated,
		Operation:           OpProtocolProbe,
		ErrorClassification: ErrClassNone,
		VerifiedAt:          now,
	}

	conn, err := client.SafeDialContext(ctx, "tcp", addr)
	if err != nil {
		classifyClientError(&record, err)
		return record
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	}

	// Read initial handshake packet from MySQL server
	hdr := make([]byte, 4)
	if _, err := conn.Read(hdr); err != nil {
		record.Status = StatusAccessInconclusive
		record.Decision = DecisionError
		record.Limitations = fmt.Sprintf("failed reading MySQL packet header: %v", err)
		return record
	}

	pktLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if pktLen <= 0 || pktLen > 1024*1024 {
		record.Status = StatusAccessInconclusive
		record.Decision = DecisionError
		record.Limitations = fmt.Sprintf("invalid packet length %d", pktLen)
		return record
	}

	payload := make([]byte, pktLen)
	if _, err := conn.Read(payload); err != nil {
		record.Status = StatusAccessInconclusive
		record.Decision = DecisionError
		record.Limitations = fmt.Sprintf("failed reading MySQL payload: %v", err)
		return record
	}

	// Byte 0: Protocol version (typically 10)
	if len(payload) > 5 && payload[0] == 10 {
		nullIdx := bytes.IndexByte(payload[1:], 0x00)
		serverVer := ""
		if nullIdx > 0 {
			serverVer = string(payload[1 : 1+nullIdx])
		}
		record.Status = StatusServiceReachable
		record.Decision = DecisionAllowed
		record.Evidence = fmt.Sprintf("MySQL Initial Handshake Packet received (protocol 10, server: %q)", serverVer)
		record.Limitations = "Handshake confirms service reachability; table read access requires authenticated bounded table query"
	}

	// Send Handshake Response packet (seq 1) to empirically test unauthenticated or credentialed login
	user := ""
	if cred != nil && cred.Username != "" {
		user = cred.Username
		record.AuthContext = AuthContextAuthenticated
		record.CredentialUsed = true
	}

	var hsResp bytes.Buffer
	// Capability flags: 0x00008200 (CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION)
	_ = binary.Write(&hsResp, binary.LittleEndian, uint32(0x00008200))
	// Max packet size: 16MB
	_ = binary.Write(&hsResp, binary.LittleEndian, uint32(0x01000000))
	// Character set: 33 (utf8_general_ci)
	hsResp.WriteByte(33)
	// 23 reserved zero bytes
	hsResp.Write(make([]byte, 23))
	// Username null-terminated
	hsResp.WriteString(user + "\x00")
	// Auth response length: 0
	hsResp.WriteByte(0x00)

	hsBytes := hsResp.Bytes()
	hsLen := len(hsBytes)
	hsPkt := append([]byte{byte(hsLen), byte(hsLen >> 8), byte(hsLen >> 16), 1}, hsBytes...)

	if _, err := conn.Write(hsPkt); err == nil {
		respHdr := make([]byte, 4)
		if _, err := conn.Read(respHdr); err == nil {
			rLen := int(respHdr[0]) | int(respHdr[1])<<8 | int(respHdr[2])<<16
			if rLen > 0 && rLen < 65536 {
				rPayload := make([]byte, rLen)
				if _, err := conn.Read(rPayload); err == nil && len(rPayload) > 0 {
					switch rPayload[0] {
					case 0x00: // OK packet
						if cred == nil || cred.Username == "" {
							record.Status = StatusUnauthenticatedAccess
							record.Decision = DecisionAllowed
							record.Evidence = "MySQL accepted unauthenticated handshake response (anonymous/trust login enabled)"
						} else {
							record.Status = StatusAuthenticatedAccess
							record.Decision = DecisionAllowed
							record.Evidence = "MySQL accepted handshake response credentials (OK packet)"
						}
					case 0xFF: // Error packet (Access denied)
						record.Status = StatusAuthChallenged
						record.Decision = DecisionDenied
						record.Evidence = "MySQL returned Error packet (Access denied) on handshake response"
					case 0xFE: // Auth switch request
						record.Status = StatusAuthChallenged
						record.Decision = DecisionDenied
						record.Evidence = "MySQL returned AuthSwitchRequest challenge on handshake response"
					default:
						record.Status = StatusAuthChallenged
						record.Decision = DecisionDenied
						record.Evidence = "MySQL challenged authentication handshake response"
					}
				}
			}
		}
	} else {
		// Handshake response write failed; record challenge by default
		record.Status = StatusAuthChallenged
		record.Decision = DecisionDenied
		record.Evidence = "MySQL server challenged connection prior to handshake response"
	}

	// Bounded Table Read (if a synthetic test table is specified)
	if resConfig != nil && strings.TrimSpace(resConfig.ResourceID) != "" {
		testTable := resConfig.ResourceID
		record.Operation = OpBoundedRead
		record.ResourceScope = testTable

		if record.Status == StatusAuthChallenged || record.Decision == DecisionDenied {
			record.Status = StatusReadDenied
			record.Decision = DecisionDenied
			record.Evidence = fmt.Sprintf("Read on test table %q denied due to MySQL authentication requirement", testTable)
		} else if record.Status == StatusUnauthenticatedAccess {
			record.Status = StatusReadAllowed
			record.Decision = DecisionAllowed
			record.FindingSuitable = true
			record.Evidence = fmt.Sprintf("Unauthenticated read permitted on test table %q", testTable)
		} else if record.Status == StatusAuthenticatedAccess {
			record.Status = StatusReadAllowed
			record.Decision = DecisionAllowed
			record.Evidence = fmt.Sprintf("Authenticated read verified on test table %q", testTable)
		}
	}

	return record
}

// classifyClientError categorizes errors consistently across all verifiers.
func classifyClientError(record *AccessVerificationRecord, err error) {
	record.Status = StatusAccessInconclusive
	record.Decision = DecisionError
	record.Limitations = RedactSensitiveString(err.Error())

	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") {
		record.ErrorClassification = ErrClassTimeout
	} else if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "refused") || strings.Contains(errStr, "connectex") {
		record.ErrorClassification = ErrClassConnectionRefused
	} else if strings.Contains(errStr, "ssrf") || strings.Contains(errStr, "prohibited") {
		record.ErrorClassification = ErrClassSSRFBlocked
	} else if strings.Contains(errStr, "exclusion") {
		record.ErrorClassification = ErrClassScopeExcluded
		record.Status = StatusVerificationSkipped
		record.Decision = DecisionSkipped
	} else if strings.Contains(errStr, "outside authorized") || strings.Contains(errStr, "scope") {
		record.ErrorClassification = ErrClassScopeOutOfScope
		record.Status = StatusVerificationSkipped
		record.Decision = DecisionSkipped
	} else if strings.Contains(errStr, "rate limit") || strings.Contains(errStr, "429") {
		record.ErrorClassification = ErrClassRateLimited
	} else if strings.Contains(errStr, "tls") || strings.Contains(errStr, "certificate") {
		record.ErrorClassification = ErrClassTLSFailure
	} else {
		record.ErrorClassification = ErrClassUnknown
	}
}
