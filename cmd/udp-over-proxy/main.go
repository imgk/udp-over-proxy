package main

import (
	"flag"
	"io"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"time"

	"golang.org/x/net/proxy"

	"github.com/imgk/udp-over-proxy/http"
	"github.com/imgk/udp-over-proxy/natmap"
	"github.com/imgk/udp-over-proxy/shadowsocks"
	"github.com/imgk/udp-over-proxy/socks"
)

type Config struct {
	ProxyAddr  string
	TargetAddr string
	ListenAddr string
}

type Handshake func(net.Conn, string, byte, *proxy.Auth) (net.Conn, error)

func main() {
	var conf Config

	flag.StringVar(&conf.ProxyAddr, "proxy", "", "proxy address: socks://127.0.0.1:1080, http://127.0.0.1:8080")
	flag.StringVar(&conf.TargetAddr, "target", "127.0.0.1:51820", "target address")
	flag.StringVar(&conf.ListenAddr, "listen", "127.0.0.1:51820", "listen address")
	flag.Parse()

	if conf.ProxyAddr == "" {
		log.Println("run udp-over-proxy as server mode")
		go ServeTCP(conf.ListenAddr, conf.TargetAddr)
	} else {
		log.Println("run udp-over-proxy as client mode")
		proxyAddr, handshake := func() (string, Handshake) {
			addr, err := url.Parse(conf.ProxyAddr)
			if err != nil {
				log.Panic(err)
			}
			switch addr.Scheme {
			case "socks":
				log.Println("proxy wireguard to " + addr.String())
				return addr.Host, socks.Handshake
			case "http":
				log.Println("proxy wireguard to " + addr.String())
				return addr.Host, http.Handshake
			case "ss":
				log.Println("proxy wireguard to " + addr.String())
				return addr.Host, shadowsocks.Handshake
			default:
			}
			return conf.TargetAddr, func(conn net.Conn, addr string, cmd byte, auth *proxy.Auth) (net.Conn, error) { return conn, nil }
		}()
		go ServeUDP(conf.ListenAddr, conf.TargetAddr, proxyAddr, handshake)
	}

	log.Println("udp-over-proxy is running...")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh
	log.Println("udp-over-proxy is closing...")
}

func ServeTCP(addr, raddr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Panic(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		log.Println("accept connection from: " + conn.RemoteAddr().String())

		go func(c net.Conn) {
			defer c.Close()

			rc, err := net.Dial("udp", raddr)
			if err != nil {
				log.Panic(err)
			}
			defer rc.Close()

			go func() {
				buf := make([]byte, 2*1024)

				for {
					n, err := rc.Read(buf[2:])
					if err != nil {
						break
					}

					buf[0], buf[1] = byte(n>>8), byte(n)

					if _, err := c.Write(buf[:2+n]); err != nil {
						break
					}
				}

				c.SetReadDeadline(time.Now())
			}()

			buf := make([]byte, 2*1024)

			for {
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					break
				}

				n := int(buf[0])<<8 | int(buf[1])

				if _, err := io.ReadFull(c, buf[:n]); err != nil {
					break
				}

				if _, err := rc.Write(buf[:n]); err != nil {
					break
				}
			}
		}(conn)
	}
}

func ServeUDP(addr, raddr, saddr string, handshake Handshake) {
	conn, err := net.ListenUDP("udp", func() *net.UDPAddr {
		naddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			log.Panic(err)
		}
		return naddr
	}())
	if err != nil {
		log.Panic(err)
	}
	defer conn.Close()

	nm := natmap.NewNatMap()
	bb := make([]byte, 2*1024)

	for {
		n, naddr, err := conn.ReadFromUDPAddrPort(bb[2:])
		if err != nil {
			log.Println("read from with error: " + err.Error())
			continue
		}

		rc, ok := nm.Get(naddr)
		if ok {
			bb[0], bb[1] = byte(n>>8), byte(n)
			if _, err := rc.Write(bb[:2+n]); err != nil {
				rc.SetReadDeadline(time.Now())
			}
			continue
		}

		rc, err = net.Dial("tcp", saddr)
		if err != nil {
			log.Panic(err)
		}

		rc, err = handshake(rc, raddr, socks.CmdConnect, nil)
		if err != nil {
			log.Println("handshake error: " + err.Error())
			rc.Close()
			continue
		}

		nm.Add(naddr, rc)
		log.Println("serve new client from: " + naddr.String())

		go func(c *net.UDPConn, raddr netip.AddrPort, timeout time.Duration) {
			defer rc.Close()

			buf := make([]byte, 2*1024)

			for {
				rc.SetReadDeadline(time.Now().Add(timeout))

				if _, err := io.ReadFull(rc, buf[:2]); err != nil {
					break
				}

				n := int(buf[0])<<8 | int(buf[1])

				if _, err := io.ReadFull(rc, buf[:n]); err != nil {
					break
				}

				if _, err := c.WriteToUDPAddrPort(buf[:n], raddr); err != nil {
					break
				}
			}

			nm.Del(raddr)
		}(conn, naddr, 300*time.Second)
	}
}
