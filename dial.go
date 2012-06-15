package socks

import (
	"errors"
	"io"
	"net"
	"strconv"
)

const (
	PROTOCOL_VERSION = 5

	COMMAND_TCP_CONNECT = 1
	COMMAND_TCP_BIND = 2
	COMMAND_UDP = 3

	ADDRESS_TYPE_IPV4 = 1
	ADDRESS_TYPE_DOMAIN = 3
	ADDRESS_TYPE_IPV6 = 4

	STATUS_REQUEST_GRANTED = 0
	STATUS_GENERAL_FAILURE = 1
	STATUS_CONNECTION_NOT_ALLOWED = 2
	STATUS_NETWORK_UNREACHABLE = 3
	STATUS_HOST_UNREACHABLE = 4
	STATUS_CONNECTION_REFUSED = 5
	STATUS_TTL_EXPIRED = 6
	STATUS_COMMAND_NOT_SUPPORT = 7
	STATUS_ADDRESS_TYPE_NOT_SUPPORT = 8
)

var (
	ErrInvalidProxyResponse = errors.New("invalid proxy response")
)

type Proxy struct {
	Addr string
}

func (p *Proxy) Dial(inet, addr string) (net.Conn, error) {
	host, strPort, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		return nil, err
	}

	conn, err := net.Dial("tcp", p.Addr)
	if err != nil {
		return nil, err
	}

	_, err = conn.Write([]byte{PROTOCOL_VERSION, 1, 0}) // version, num auth methods, auth methods (0=noauth)
	if err != nil {
		conn.Close()
		return nil, err
	}

	buf := make([]byte, 1024)

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		conn.Close()
		return nil, err
	}
	if buf[0] != PROTOCOL_VERSION || buf[1] != 0 { // version, chosen auth method (0xff == no acceptable auth method)
		conn.Close()
		return nil, ErrInvalidProxyResponse
	}

	buf = buf[:7+len(host)]
	buf[0] = PROTOCOL_VERSION
	buf[1] = COMMAND_TCP_CONNECT
	buf[2] = 0 // reserved
	buf[3] = ADDRESS_TYPE_DOMAIN
	buf[4] = byte(len(host))
	copy(buf[5:], host)
	buf[5+len(host)] = byte(port >> 8)
	buf[6+len(host)] = byte(port & 0xff)
	_, err = conn.Write(buf)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		conn.Close()
		return nil, err
	}

	if buf[0] != PROTOCOL_VERSION {
		conn.Close()
		return nil, ErrInvalidProxyResponse
	}

	if buf[1] != STATUS_REQUEST_GRANTED {
		conn.Close()
		return nil, ErrInvalidProxyResponse
	}

	paddr := &proxiedAddr{net: inet}

	switch buf[3] {
	default:
		conn.Close()
		return nil, ErrInvalidProxyResponse
	case ADDRESS_TYPE_IPV4:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			conn.Close()
			return nil, err
		}
		paddr.host = net.IP(buf).String()
	case ADDRESS_TYPE_IPV6:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			conn.Close()
			return nil, err
		}
		paddr.host = net.IP(buf).String()
	case ADDRESS_TYPE_DOMAIN:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			conn.Close()
			return nil, err
		}
		domainLen := buf[0]
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			conn.Close()
			return nil, err
		}
		paddr.host = string(buf[:domainLen])
	}

	// Port
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		conn.Close()
		return nil, err
	}
	paddr.port = int(buf[0]) << 8 | int(buf[1])

	return &proxiedConn{conn:conn}, nil
}
