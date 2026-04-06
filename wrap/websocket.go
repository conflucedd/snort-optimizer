package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
)

const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type WebSocketConn struct {
	conn net.Conn
	mu   sync.Mutex
}

func UpgradeWebSocket(w http.ResponseWriter, r *http.Request) (*WebSocketConn, error) {
	if !headerContainsToken(r.Header, "Connection", "Upgrade") {
		return nil, fmt.Errorf("missing Connection: Upgrade")
	}
	if !headerContainsToken(r.Header, "Upgrade", "websocket") {
		return nil, fmt.Errorf("missing Upgrade: websocket")
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		return nil, fmt.Errorf("missing Sec-WebSocket-Key")
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("websocket hijacking not supported")
	}

	netConn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}

	accept := computeWebSocketAccept(key)
	response := bufio.NewWriter(netConn)
	_, _ = response.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	_, _ = response.WriteString("Upgrade: websocket\r\n")
	_, _ = response.WriteString("Connection: Upgrade\r\n")
	_, _ = response.WriteString("Sec-WebSocket-Accept: " + accept + "\r\n\r\n")
	if err := response.Flush(); err != nil {
		netConn.Close()
		return nil, err
	}
	if rw.Reader.Buffered() > 0 {
		_, _ = rw.Reader.Discard(rw.Reader.Buffered())
	}

	return &WebSocketConn{conn: netConn}, nil
}

func (c *WebSocketConn) WriteJSON(payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return c.WriteText(data)
}

func (c *WebSocketConn) WriteText(payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	header := make([]byte, 0, 10)
	header = append(header, 0x81)

	length := len(payload)
	switch {
	case length <= 125:
		header = append(header, byte(length))
	case length <= 65535:
		header = append(header, 126)
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(length))
		header = append(header, ext...)
	default:
		header = append(header, 127)
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(length))
		header = append(header, ext...)
	}

	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	_, err := c.conn.Write(payload)
	return err
}

func (c *WebSocketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.Close()
}

func computeWebSocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + websocketGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func headerContainsToken(header http.Header, key, want string) bool {
	for _, part := range strings.Split(header.Get(key), ",") {
		if strings.EqualFold(strings.TrimSpace(part), want) {
			return true
		}
	}
	return false
}
