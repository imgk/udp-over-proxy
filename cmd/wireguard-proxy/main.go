package main

import (
	"flag"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"github.com/imgk/wireguard-proxy/natmap"
	"github.com/imgk/wireguard-proxy/socks"
)

type Config struct {
	ProxyAddr  string
	TargetAddr string
	ListenAddr string
}

func main() {
	var conf Config

	flag.StringVar(&conf.ProxyAddr, "proxy", "", "proxy address")
	flag.StringVar(&conf.TargetAddr, "target", "127.0.0.1:51820", "target address")
	flag.StringVar(&conf.ListenAddr, "listen", "127.0.0.1:51820", "listen address")
	flag.Parse()

	if conf.ProxyAddr == "" {
		log.Println("run wireguard-proxy as server mode")
		go ServeTCP(conf.ListenAddr, conf.TargetAddr)
	} else {
		log.Println("run wireguard-proxy as client mode")
		go ServeUDP(conf.ListenAddr, conf.TargetAddr, conf.ProxyAddr)
	}

	log.Println("wireguard-proxy is running...")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh
	log.Println("wireguard-proxy is closing...")
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

func ServeUDP(addr, raddr, saddr string) {
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
	for {
		buf := make([]byte, 2*1024)

		n, naddr, err := conn.ReadFromUDPAddrPort(buf[2:])
		if err != nil {
			continue
		}

		rc := nm.Get(naddr)
		if rc != nil {
			buf[0], buf[1] = byte(n>>8), byte(n)
			if _, err := rc.Write(buf[:2+n]); err != nil {
			}
			continue
		}

		rc, err = net.Dial("tcp", saddr)
		if err != nil {
			log.Panic(err)
		}

		if _, err := socks.Handshake(rc, func() net.Addr {
			naddr, err := net.ResolveTCPAddr("tcp", raddr)
			if err != nil {
				log.Panic(err)
			}
			addr, err := socks.ResolveAddr(naddr)
			if err != nil {
				log.Panic(err)
			}
			return addr
		}(), socks.CmdConnect, nil); err != nil {
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
				}

				n := int(buf[0])<<8 | int(buf[1])

				if _, err := io.ReadFull(rc, buf[:n]); err != nil {
				}

				if _, err := c.WriteToUDPAddrPort(buf[:n], raddr); err != nil {
				}
			}

			nm.Del(naddr)
		}(conn, naddr, 300*time.Second)
	}
}
