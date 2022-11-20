package natmap

import (
	"net"
	"net/netip"
	"sync"
)

type NatMap struct {
	sync.RWMutex
	nm map[netip.AddrPort]net.Conn
}

func NewNatMap() *NatMap {
	return &NatMap{
		nm: make(map[netip.AddrPort]net.Conn),
	}
}

func (nm *NatMap) Get(addr netip.AddrPort) net.Conn {
	nm.RLock()
	defer nm.RUnlock()

	return nm.nm[addr]
}

func (nm *NatMap) Add(addr netip.AddrPort, conn net.Conn) {
	nm.Lock()
	defer nm.Unlock()

	nm.nm[addr] = conn
}

func (nm *NatMap) Del(addr netip.AddrPort) net.Conn {
	nm.Lock()
	defer nm.Unlock()

	conn, ok := nm.nm[addr]
	if ok {
		delete(nm.nm, addr)
	}
	return conn
}
