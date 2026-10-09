package qafas

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/coder/websocket"
)

// ErrNotFound is returned (wrapped, so use errors.Is) by ReadFile, Stat and ListDir
// when the path does not exist (HTTP 404).
var ErrNotFound = errors.New("not found")

var (
	clientMu sync.Mutex
	clients  = map[string]*http.Client{} // by SBX_CA_FILE value
)

// httpClient trusts the system roots plus $SBX_CA_FILE (the CA an https control plane
// or worker chains to, e.g. an internal PKI). No client timeout: callers bound calls with ctx.
func httpClient() (*http.Client, error) {
	ca := os.Getenv("SBX_CA_FILE")
	clientMu.Lock()
	defer clientMu.Unlock()
	if c, ok := clients[ca]; ok {
		return c, nil
	}
	c := &http.Client{}
	if ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("SBX_CA_FILE: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("SBX_CA_FILE %s: no PEM certificate found", ca)
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
		c.Transport = tr
	}
	clients[ca] = c
	return c, nil
}

// do performs one request and returns the status and the whole body.
func do(ctx context.Context, method, u string, headers map[string]string, body []byte) (int, []byte, error) {
	hc, err := httpClient()
	if err != nil {
		return 0, nil, err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return resp.StatusCode, data, err
}

// call is do, with any status >= 400 turned into an *Error.
func call(ctx context.Context, method, u string, headers map[string]string, body []byte) ([]byte, error) {
	status, data, err := do(ctx, method, u, headers, body)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, &Error{Status: status, Body: string(data)}
	}
	return data, nil
}

// callJSON sends in (when non-nil) as JSON and decodes a non-empty reply into out (when non-nil).
func callJSON(ctx context.Context, method, u string, headers map[string]string, in, out any) error {
	var body []byte
	h := headers
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = b
		h = make(map[string]string, len(headers)+1)
		for k, v := range headers {
			h[k] = v
		}
		h["content-type"] = "application/json"
	}
	data, err := call(ctx, method, u, h, body)
	if err != nil || out == nil || len(data) == 0 {
		return err
	}
	return json.Unmarshal(data, out)
}

// quote percent-encodes a query value like Python's urllib.parse.quote ("/" stays).
func quote(s string) string {
	const safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~/"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(safe, s[i]) >= 0 {
			b.WriteByte(s[i])
		} else {
			fmt.Fprintf(&b, "%%%02X", s[i])
		}
	}
	return b.String()
}

func pathSeg(s string) string { return url.PathEscape(s) }

// wsURL turns an http(s) URL into ws(s).
func wsURL(u string) string { return strings.Replace(u, "http", "ws", 1) }

// dialWS opens a WebSocket (trusting $SBX_CA_FILE for wss). A refused upgrade comes
// back as an *Error carrying the HTTP status.
func dialWS(ctx context.Context, u string, headers map[string]string) (*websocket.Conn, error) {
	hc, err := httpClient()
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	c, resp, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: hc, HTTPHeader: h})
	if err != nil {
		if resp != nil && resp.StatusCode >= 400 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
			return nil, &Error{Status: resp.StatusCode, Body: string(b)}
		}
		return nil, err
	}
	c.SetReadLimit(1 << 26) // default 32 KiB is far below one base64 output frame
	return c, nil
}

// wsDone reports whether a Read error is just the peer closing normally.
func wsDone(err error) bool {
	s := websocket.CloseStatus(err)
	return s == websocket.StatusNormalClosure || s == websocket.StatusGoingAway
}

// lossy decodes bytes as UTF-8, replacing each invalid byte with U+FFFD.
func lossy(b []byte) string { return string([]rune(string(b))) }
