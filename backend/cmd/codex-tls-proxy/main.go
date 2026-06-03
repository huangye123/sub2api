package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultListenAddr     = "127.0.0.1:18080"
	defaultCaptureTimeout = 5 * time.Second
	defaultConnectTimeout = 15 * time.Second
	maxClientHelloBytes   = 256 * 1024
)

type tlsProfilePayload struct {
	Name                string   `json:"name"`
	Description         string   `json:"description,omitempty"`
	EnableGREASE        bool     `json:"enable_grease"`
	CipherSuites        []uint16 `json:"cipher_suites"`
	Curves              []uint16 `json:"curves"`
	PointFormats        []uint16 `json:"point_formats"`
	SignatureAlgorithms []uint16 `json:"signature_algorithms"`
	ALPNProtocols       []string `json:"alpn_protocols"`
	SupportedVersions   []uint16 `json:"supported_versions"`
	KeyShareGroups      []uint16 `json:"key_share_groups"`
	PSKModes            []uint16 `json:"psk_modes"`
	Extensions          []uint16 `json:"extensions"`
}

type capturedHello struct {
	Profile    tlsProfilePayload
	Host       string
	ServerName string
	JA3Raw     string
	JA3Hash    string
}

type proxyServer struct {
	listenAddr     string
	outputPath     string
	profileName    string
	description    string
	matchHosts     []string
	once           bool
	sub2apiURL     string
	adminToken     string
	captureTimeout time.Duration
	connectTimeout time.Duration
	verbose        bool

	captured atomic.Bool
	cancel   context.CancelFunc
}

type apiResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func main() {
	var opts proxyServer
	flag.StringVar(&opts.listenAddr, "listen", defaultListenAddr, "HTTP CONNECT proxy listen address")
	flag.StringVar(&opts.outputPath, "out", "codex-tls-profile.json", "file to write the importable TLS profile JSON; use '-' for stdout")
	outputFormat := flag.String("format", "json", "output format: json or yaml")
	flag.StringVar(&opts.profileName, "name", "codex_captured", "TLS fingerprint profile name")
	flag.StringVar(&opts.description, "description", "Captured from Codex through codex-tls-proxy", "profile description")
	match := flag.String("match", "", "comma-separated host substrings to capture; empty captures the first TLS CONNECT")
	flag.BoolVar(&opts.once, "once", true, "stop listening after the first matching ClientHello is captured")
	flag.StringVar(&opts.sub2apiURL, "sub2api-url", "", "optional Sub2API base URL used to import the profile, for example http://127.0.0.1:8080")
	flag.StringVar(&opts.adminToken, "admin-token", os.Getenv("SUB2API_ADMIN_TOKEN"), "Sub2API admin JWT; defaults to SUB2API_ADMIN_TOKEN")
	flag.DurationVar(&opts.captureTimeout, "capture-timeout", defaultCaptureTimeout, "timeout while waiting for the CONNECT TLS ClientHello")
	flag.DurationVar(&opts.connectTimeout, "connect-timeout", defaultConnectTimeout, "timeout for connecting to the requested upstream host")
	flag.BoolVar(&opts.verbose, "v", false, "enable verbose logs")
	flag.Parse()

	opts.matchHosts = splitCSV(*match)
	if *outputFormat != "json" && *outputFormat != "yaml" {
		log.Fatalf("unsupported -format %q; use json or yaml", *outputFormat)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, opts.cancel = context.WithCancel(ctx)
	defer opts.cancel()

	if err := opts.run(ctx, *outputFormat); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("codex-tls-proxy failed: %v", err)
	}
}

func (p *proxyServer) run(ctx context.Context, outputFormat string) error {
	ln, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Printf("codex TLS capture proxy listening on http://%s", p.listenAddr)
	log.Printf("run Codex with HTTPS_PROXY=http://%s", p.listenAddr)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("accept failed: %v", err)
			continue
		}
		go p.handleConn(ctx, conn, outputFormat)
	}
}

func (p *proxyServer) handleConn(ctx context.Context, client net.Conn, outputFormat string) {
	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		_ = client.Close()
		if p.verbose {
			log.Printf("read proxy request failed: %v", err)
		}
		return
	}

	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(client, "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
		_ = client.Close()
		return
	}

	target := req.Host
	if !strings.Contains(target, ":") {
		target = net.JoinHostPort(target, "443")
	}

	_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")

	prefix, hello, err := readAndParseClientHello(client, br, p.captureTimeout)
	if err != nil {
		log.Printf("capture %s failed: %v", target, err)
		_ = client.Close()
		return
	}
	hello.Host = target

	if p.shouldCapture(target, hello.ServerName) {
		p.onCapture(ctx, hello, outputFormat)
	} else if p.verbose {
		log.Printf("skipped ClientHello for host=%s sni=%s", target, hello.ServerName)
	}

	upstream, err := net.DialTimeout("tcp", target, p.connectTimeout)
	if err != nil {
		log.Printf("connect upstream %s failed: %v", target, err)
		_ = client.Close()
		return
	}

	if len(prefix) > 0 {
		if _, err := upstream.Write(prefix); err != nil {
			log.Printf("forward ClientHello to %s failed: %v", target, err)
			_ = upstream.Close()
			_ = client.Close()
			return
		}
	}

	go copyAndClose(upstream, io.MultiReader(br, client))
	copyAndClose(client, upstream)

	if p.once && p.captured.Load() {
		p.cancel()
	}
}

func (p *proxyServer) shouldCapture(host, sni string) bool {
	if p.captured.Load() && p.once {
		return false
	}
	if len(p.matchHosts) == 0 {
		return true
	}
	host = strings.ToLower(host)
	sni = strings.ToLower(sni)
	for _, m := range p.matchHosts {
		if strings.Contains(host, m) || strings.Contains(sni, m) {
			return true
		}
	}
	return false
}

func (p *proxyServer) onCapture(ctx context.Context, hello capturedHello, outputFormat string) {
	if p.once && p.captured.Swap(true) {
		return
	}
	hello.Profile.Name = p.profileName
	hello.Profile.Description = buildDescription(p.description, hello)

	if err := writeProfile(p.outputPath, outputFormat, hello.Profile); err != nil {
		log.Printf("write profile failed: %v", err)
	} else if p.outputPath != "-" {
		log.Printf("wrote importable TLS profile to %s", p.outputPath)
	}

	log.Printf("captured ClientHello host=%s sni=%s ja3_hash=%s", hello.Host, hello.ServerName, hello.JA3Hash)

	if strings.TrimSpace(p.sub2apiURL) != "" {
		if err := importProfile(ctx, p.sub2apiURL, p.adminToken, hello.Profile); err != nil {
			log.Printf("Sub2API import failed: %v", err)
		} else {
			log.Printf("imported TLS profile into Sub2API")
		}
	}

}

func buildDescription(base string, hello capturedHello) string {
	parts := []string{}
	if strings.TrimSpace(base) != "" {
		parts = append(parts, strings.TrimSpace(base))
	}
	if hello.ServerName != "" {
		parts = append(parts, "SNI: "+hello.ServerName)
	}
	if hello.JA3Hash != "" {
		parts = append(parts, "JA3: "+hello.JA3Hash)
	}
	return strings.Join(parts, " | ")
}

func readAndParseClientHello(conn net.Conn, r io.Reader, timeout time.Duration) ([]byte, capturedHello, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})

	var prefix bytes.Buffer
	var payload bytes.Buffer

	for prefix.Len() < maxClientHelloBytes {
		header := make([]byte, 5)
		if _, err := io.ReadFull(r, header); err != nil {
			return prefix.Bytes(), capturedHello{}, err
		}
		prefix.Write(header)

		if header[0] != 22 {
			return prefix.Bytes(), capturedHello{}, fmt.Errorf("expected TLS handshake record, got content type %d", header[0])
		}
		recordLen := int(header[3])<<8 | int(header[4])
		if recordLen <= 0 || prefix.Len()+recordLen > maxClientHelloBytes {
			return prefix.Bytes(), capturedHello{}, fmt.Errorf("invalid TLS record length %d", recordLen)
		}

		record := make([]byte, recordLen)
		if _, err := io.ReadFull(r, record); err != nil {
			return prefix.Bytes(), capturedHello{}, err
		}
		prefix.Write(record)
		payload.Write(record)

		if payload.Len() >= 4 {
			b := payload.Bytes()
			if b[0] != 1 {
				return prefix.Bytes(), capturedHello{}, fmt.Errorf("expected ClientHello handshake, got type %d", b[0])
			}
			helloLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
			if helloLen < 0 || helloLen > maxClientHelloBytes {
				return prefix.Bytes(), capturedHello{}, fmt.Errorf("invalid ClientHello length %d", helloLen)
			}
			if payload.Len() >= 4+helloLen {
				hello, err := parseClientHello(b[4 : 4+helloLen])
				return prefix.Bytes(), hello, err
			}
		}
	}

	return prefix.Bytes(), capturedHello{}, fmt.Errorf("ClientHello exceeded %d bytes", maxClientHelloBytes)
}

func parseClientHello(body []byte) (capturedHello, error) {
	var out capturedHello
	var off int
	readU8 := func() (uint8, error) {
		if off+1 > len(body) {
			return 0, io.ErrUnexpectedEOF
		}
		v := body[off]
		off++
		return v, nil
	}
	readU16 := func() (uint16, error) {
		if off+2 > len(body) {
			return 0, io.ErrUnexpectedEOF
		}
		v := uint16(body[off])<<8 | uint16(body[off+1])
		off += 2
		return v, nil
	}
	readBytes := func(n int) ([]byte, error) {
		if n < 0 || off+n > len(body) {
			return nil, io.ErrUnexpectedEOF
		}
		v := body[off : off+n]
		off += n
		return v, nil
	}

	if _, err := readU16(); err != nil { // legacy_version
		return out, err
	}
	if _, err := readBytes(32); err != nil { // random
		return out, err
	}
	sessionLen, err := readU8()
	if err != nil {
		return out, err
	}
	if _, err := readBytes(int(sessionLen)); err != nil {
		return out, err
	}

	cipherLen, err := readU16()
	if err != nil {
		return out, err
	}
	if cipherLen%2 != 0 {
		return out, fmt.Errorf("invalid cipher suite length %d", cipherLen)
	}
	for i := 0; i < int(cipherLen)/2; i++ {
		v, err := readU16()
		if err != nil {
			return out, err
		}
		if isGREASEValue(v) {
			out.Profile.EnableGREASE = true
		}
		out.Profile.CipherSuites = append(out.Profile.CipherSuites, v)
	}

	compressionLen, err := readU8()
	if err != nil {
		return out, err
	}
	if _, err := readBytes(int(compressionLen)); err != nil {
		return out, err
	}
	if off == len(body) {
		out.JA3Raw, out.JA3Hash = computeJA3(out.Profile)
		return out, nil
	}

	extensionsLen, err := readU16()
	if err != nil {
		return out, err
	}
	extensionsEnd := off + int(extensionsLen)
	if extensionsEnd > len(body) {
		return out, io.ErrUnexpectedEOF
	}

	for off < extensionsEnd {
		extType, err := readU16()
		if err != nil {
			return out, err
		}
		extLen, err := readU16()
		if err != nil {
			return out, err
		}
		extData, err := readBytes(int(extLen))
		if err != nil {
			return out, err
		}
		if isGREASEValue(extType) {
			out.Profile.EnableGREASE = true
		}
		out.Profile.Extensions = append(out.Profile.Extensions, extType)
		parseExtension(extType, extData, &out)
	}
	if off != extensionsEnd {
		return out, fmt.Errorf("invalid extensions length")
	}

	out.JA3Raw, out.JA3Hash = computeJA3(out.Profile)
	return out, nil
}

func parseExtension(extType uint16, data []byte, out *capturedHello) {
	switch extType {
	case 0:
		out.ServerName = parseSNI(data)
	case 10:
		out.Profile.Curves = parseU16List(data, 2, func(v uint16) {
			if isGREASEValue(v) {
				out.Profile.EnableGREASE = true
			}
		})
	case 11:
		if len(data) < 1 {
			return
		}
		n := int(data[0])
		if 1+n > len(data) {
			return
		}
		for _, b := range data[1 : 1+n] {
			out.Profile.PointFormats = append(out.Profile.PointFormats, uint16(b))
		}
	case 13:
		out.Profile.SignatureAlgorithms = parseU16List(data, 2, nil)
	case 16:
		out.Profile.ALPNProtocols = parseALPN(data)
	case 43:
		if len(data) < 1 {
			return
		}
		n := int(data[0])
		if 1+n > len(data) || n%2 != 0 {
			return
		}
		for i := 1; i < 1+n; i += 2 {
			v := uint16(data[i])<<8 | uint16(data[i+1])
			if isGREASEValue(v) {
				out.Profile.EnableGREASE = true
			}
			out.Profile.SupportedVersions = append(out.Profile.SupportedVersions, v)
		}
	case 45:
		if len(data) < 1 {
			return
		}
		n := int(data[0])
		if 1+n > len(data) {
			return
		}
		for _, b := range data[1 : 1+n] {
			out.Profile.PSKModes = append(out.Profile.PSKModes, uint16(b))
		}
	case 51:
		out.Profile.KeyShareGroups = parseKeyShareGroups(data, out)
	}
}

func parseSNI(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	listLen := int(data[0])<<8 | int(data[1])
	pos := 2
	end := pos + listLen
	if end > len(data) {
		return ""
	}
	for pos+3 <= end {
		nameType := data[pos]
		nameLen := int(data[pos+1])<<8 | int(data[pos+2])
		pos += 3
		if pos+nameLen > end {
			return ""
		}
		if nameType == 0 {
			return string(data[pos : pos+nameLen])
		}
		pos += nameLen
	}
	return ""
}

func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	pos := 2
	end := pos + listLen
	if end > len(data) {
		return nil
	}
	var out []string
	for pos < end {
		if pos+1 > end {
			return nil
		}
		n := int(data[pos])
		pos++
		if pos+n > end {
			return nil
		}
		out = append(out, string(data[pos:pos+n]))
		pos += n
	}
	return out
}

func parseU16List(data []byte, lenBytes int, onValue func(uint16)) []uint16 {
	if len(data) < lenBytes {
		return nil
	}
	var n, pos int
	switch lenBytes {
	case 1:
		n = int(data[0])
		pos = 1
	case 2:
		n = int(data[0])<<8 | int(data[1])
		pos = 2
	default:
		return nil
	}
	if pos+n > len(data) || n%2 != 0 {
		return nil
	}
	out := make([]uint16, 0, n/2)
	for i := pos; i < pos+n; i += 2 {
		v := uint16(data[i])<<8 | uint16(data[i+1])
		if onValue != nil {
			onValue(v)
		}
		out = append(out, v)
	}
	return out
}

func parseKeyShareGroups(data []byte, out *capturedHello) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	pos := 2
	end := pos + listLen
	if end > len(data) {
		return nil
	}
	var groups []uint16
	for pos+4 <= end {
		group := uint16(data[pos])<<8 | uint16(data[pos+1])
		keyLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4
		if pos+keyLen > end {
			return nil
		}
		if isGREASEValue(group) {
			out.Profile.EnableGREASE = true
		}
		groups = append(groups, group)
		pos += keyLen
	}
	return groups
}

func computeJA3(profile tlsProfilePayload) (string, string) {
	parts := []string{
		"771",
		joinU16(filterGREASE(profile.CipherSuites), "-"),
		joinU16(filterGREASE(profile.Extensions), "-"),
		joinU16(filterGREASE(profile.Curves), "-"),
		joinU16(profile.PointFormats, "-"),
	}
	raw := strings.Join(parts, ",")
	sum := md5.Sum([]byte(raw))
	return raw, hex.EncodeToString(sum[:])
}

func filterGREASE(vals []uint16) []uint16 {
	out := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if !isGREASEValue(v) {
			out = append(out, v)
		}
	}
	return out
}

func isGREASEValue(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func joinU16(vals []uint16, sep string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, sep)
}

func writeProfile(path, format string, profile tlsProfilePayload) error {
	var body []byte
	switch format {
	case "json":
		var err error
		body, err = json.MarshalIndent(profile, "", "  ")
		if err != nil {
			return err
		}
	case "yaml":
		body = []byte(formatProfileYAML(profile))
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}
	body = append(body, '\n')
	if path == "-" {
		_, err := os.Stdout.Write(body)
		return err
	}
	return os.WriteFile(path, body, 0644)
}

func formatProfileYAML(profile tlsProfilePayload) string {
	var b strings.Builder
	key := sanitizeProfileKey(profile.Name)
	if key == "" {
		key = "codex_captured"
	}
	fmt.Fprintf(&b, "%s:\n", key)
	writeYAMLString(&b, "name", profile.Name)
	writeYAMLString(&b, "description", profile.Description)
	fmt.Fprintf(&b, "  enable_grease: %t\n", profile.EnableGREASE)
	writeYAMLUint16Array(&b, "cipher_suites", profile.CipherSuites)
	writeYAMLUint16Array(&b, "curves", profile.Curves)
	writeYAMLUint16Array(&b, "point_formats", profile.PointFormats)
	writeYAMLUint16Array(&b, "signature_algorithms", profile.SignatureAlgorithms)
	writeYAMLStringArray(&b, "alpn_protocols", profile.ALPNProtocols)
	writeYAMLUint16Array(&b, "supported_versions", profile.SupportedVersions)
	writeYAMLUint16Array(&b, "key_share_groups", profile.KeyShareGroups)
	writeYAMLUint16Array(&b, "psk_modes", profile.PSKModes)
	writeYAMLUint16Array(&b, "extensions", profile.Extensions)
	return strings.TrimRight(b.String(), "\n")
}

func sanitizeProfileKey(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	var b strings.Builder
	lastUnderscore := false
	for _, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}

func writeYAMLString(b *strings.Builder, key, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	encoded, _ := json.Marshal(value)
	fmt.Fprintf(b, "  %s: %s\n", key, encoded)
}

func writeYAMLUint16Array(b *strings.Builder, key string, vals []uint16) {
	fmt.Fprintf(b, "  %s: [", key)
	for i, v := range vals {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(b, "%d", v)
	}
	b.WriteString("]\n")
}

func writeYAMLStringArray(b *strings.Builder, key string, vals []string) {
	fmt.Fprintf(b, "  %s: [", key)
	for i, v := range vals {
		if i > 0 {
			b.WriteString(", ")
		}
		encoded, _ := json.Marshal(v)
		b.Write(encoded)
	}
	b.WriteString("]\n")
}

func importProfile(ctx context.Context, baseURL, token string, profile tlsProfilePayload) error {
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("missing admin token; pass -admin-token or set SUB2API_ADMIN_TOKEN")
	}
	endpoint, err := tlsProfileImportURL(baseURL)
	if err != nil {
		return err
	}
	body, err := json.Marshal(profile)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var api apiResponse
	if err := json.Unmarshal(respBody, &api); err != nil {
		return err
	}
	if api.Code != 0 {
		return fmt.Errorf("API code %d: %s", api.Code, api.Message)
	}
	return nil
}

func tlsProfileImportURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid Sub2API URL %q", raw)
	}
	path := strings.TrimRight(u.Path, "/")
	switch {
	case path == "":
		u.Path = "/api/v1/admin/tls-fingerprint-profiles"
	case strings.HasSuffix(path, "/api/v1"):
		u.Path = path + "/admin/tls-fingerprint-profiles"
	case strings.HasSuffix(path, "/admin"):
		u.Path = path + "/tls-fingerprint-profiles"
	case strings.HasSuffix(path, "/tls-fingerprint-profiles"):
		u.Path = path
	default:
		u.Path = path + "/api/v1/admin/tls-fingerprint-profiles"
	}
	return u.String(), nil
}

func copyAndClose(dst net.Conn, src io.Reader) {
	_, _ = io.Copy(dst, src)
	_ = dst.Close()
	if c, ok := src.(io.Closer); ok {
		_ = c.Close()
	}
}

func splitCSV(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
