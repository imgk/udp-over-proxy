package shadowsocks

import (
	"net"

	"golang.org/x/net/proxy"

	"github.com/imgk/udp-over-proxy/socks"

	"github.com/shadowsocks/go-shadowsocks2/core"
)

func Handshake(conn net.Conn, tgt string, cmd byte, auth *proxy.Auth) (net.Conn, error) {
	ciph, err := core.PickCipher(auth.User, nil, auth.Password)
	if err != nil {
		return nil, err
	}

	conn = ciph.StreamConn(conn)

	addr, err := socks.ResolveAddr(&socks.StringAddr{Addr: tgt})
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write(addr.Addr); err != nil {
		return nil, err
	}

	return conn, nil
}
