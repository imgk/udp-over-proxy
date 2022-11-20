package http

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"golang.org/x/net/proxy"
)

func Handshake(conn net.Conn, tgt string, cmd byte, auth *proxy.Auth) (net.Conn, error) {
	req, err := http.NewRequest(http.MethodConnect, "", nil)
	if err != nil {
		return nil, err
	}
	req.Host = tgt
	if auth != nil {
		req.Header.Add("Proxy-Authorization", func() string {
			proxyAuth := fmt.Sprintf("%v:%v", auth.User, auth.Password)
			return fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(proxyAuth)))
		}())
	}

	if err := req.Write(conn); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	r, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, err
	}
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http response code error: %v", r.StatusCode)
	}
	if n := reader.Buffered(); n > 0 {
		b := make([]byte, n)
		if _, err = io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		return &rawConn{Conn: conn, Reader: bytes.NewReader(b)}, nil
	}

	return conn, nil
}

// rawConn is ...
type rawConn struct {
	net.Conn
	Reader *bytes.Reader
}

// Read is ...
func (c *rawConn) Read(b []byte) (int, error) {
	if c.Reader == nil {
		return c.Conn.Read(b)
	}
	n, err := c.Reader.Read(b)
	if err != nil {
		if errors.Is(err, io.EOF) {
			c.Reader = nil
			err = nil
		}
	}
	return n, err
}
