package socks5

import (
	"net"
	"time"
)

type proxiedConn struct {
	conn net.Conn
	addr *proxiedAddr
}

func (c *proxiedConn) Read(b []byte) (int, error) {
	return c.conn.Read(b)
}

func (c *proxiedConn) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *proxiedConn) Close() error {
	return c.conn.Close()
}

func (c *proxiedConn) LocalAddr() net.Addr {
	return c.LocalAddr()
}

func (c *proxiedConn) RemoteAddr() net.Addr {
	return c.addr
}

func (c *proxiedConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *proxiedConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *proxiedConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
