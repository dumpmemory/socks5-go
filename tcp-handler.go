package socks5

import (
	"context"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// support for CMD BIND
func (s *TCPConn) HandleBIND(conn net.Conn, req *TCPRequest) {
	//launch listener on proxy server side
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return
	}
	//first reply,client get host side listener address and to notify dest server to connect to proxy server side listener
	s.sendReply(conn, listener.Addr().(*net.TCPAddr).IP, listener.Addr().(*net.TCPAddr).Port, 0)
	//server -> client
	//dest server connect to host
	targetConn, err := listener.Accept()
	if err != nil {
		return
	}
	//sec reply
	s.sendReply(conn, targetConn.RemoteAddr().(*net.TCPAddr).IP, targetConn.RemoteAddr().(*net.TCPAddr).Port, 0)
	s.RegisterTCPRequest(req)
	closeChan := make(chan error, 2)
	//transport data within client and dest
	s.TCPTransport(conn, targetConn, closeChan)
	for range [2]struct{}{} {
		<-closeChan
	}
	s.DelTCPRequest(req.TargetAddr.String())
}

// support for CMD CONNECT
func (s *TCPConn) HandleCONNECT(conn net.Conn, req *TCPRequest) {
	targetConn, err := s.DialTCP(req.TargetAddr)
	if err != nil {
		s.sendReply(conn, req.TargetAddr.IP, req.TargetAddr.Port, 3)
		return
	}
	req.TargetConn = targetConn
	s.RegisterTCPRequest(req)
	closeChan := make(chan error, 2)
	//asynchronous transport launch
	s.TCPTransport(conn, targetConn, closeChan)
	//reply
	s.sendReply(conn, targetConn.LocalAddr().(*net.TCPAddr).IP, targetConn.LocalAddr().(*net.TCPAddr).Port, 0)
	//error handling
	for range [2]struct{}{} {
		<-closeChan
	}
	s.DelTCPRequest(req.TargetAddr.String())
}

// Concurrently TCP traffic transport with 3 reading timeout
func (s *TCPConn) TCPTransport(clientConn, remoteConn net.Conn, closeChan chan error) {
	go func() {
		limit := TCPRETRY
		remoteConn.SetReadDeadline(time.Time{})
		for {
			n, err := io.Copy(clientConn, remoteConn)
			if err != nil {
				if errors.Is(err, io.EOF) ||
					strings.Contains(err.Error(), "timeout") ||
					strings.Contains(err.Error(), "closed") ||
					limit <= 0 {
					closeChan <- err
					return
				}
				time.Sleep(time.Second * 5)
				limit--
				continue
			}
			if n == 0 {
				time.Sleep(time.Second * 3)
				continue
			}
			log.Printf("[ID:%v][TCP]remote:%v send %v bytes -> client:%v\n", s.ID(), remoteConn.RemoteAddr(), n, clientConn.RemoteAddr())
		}
	}()
	go func() {
		limit := TCPRETRY
		clientConn.SetReadDeadline(time.Time{})
		for {
			n, err := io.Copy(remoteConn, clientConn)
			if err != nil {
				if errors.Is(err, io.EOF) ||
					strings.Contains(err.Error(), "timeout") ||
					strings.Contains(err.Error(), "closed") ||
					limit <= 0 {
					closeChan <- err
					return
				}
				time.Sleep(time.Second * 5)
				limit--
				continue
			}
			if n == 0 {
				time.Sleep(time.Second * 3)
				continue
			}
			log.Printf("[ID:%v][TCP]client:%v send %v bytes -> remote:%v\n", s.ID(), clientConn.RemoteAddr(), n, remoteConn.RemoteAddr())
		}
	}()
}

/*
+----+-----+-------+------+----------+----------+

	|VER | REP | RSV | ATYP | BND.ADDR | BND.PORT |
	+----+-----+-------+------+----------+----------+
	| 1 | 1 | X’00’ | 1 | Variable | 2 |
	+----+-----+-------+------+----------+----------+
*/
func (s *TCPConn) sendReply(conn net.Conn, addrIP net.IP, addrPort int, resp int) {
	var (
		addrATYP byte
		addrBody []byte
	)
	switch {
	case addrIP == nil || addrIP.To4() != nil:
		addrATYP = atypIPV4
		addrBody = addrIP.To4()
		if addrBody == nil {
			addrBody = []byte{0, 0, 0, 0}
		}
	case addrIP.To16() != nil:
		addrATYP = atypIPV6
		addrBody = addrIP.To16()
	default:
		log.Printf("[ID:%v]failed to format address.", s.ID())
		return
	}

	msg := []byte{
		byte(SOCKS5VERSION),
		byte(resp),
		byte(0),
		addrATYP,
	}
	msg = append(msg, addrBody...)
	msg = append(msg, byte(addrPort>>8), byte(addrPort&0xff))

	if _, err := conn.Write(msg); err != nil {
		log.Printf("[ID:%v]%v", s.ID(), err)
	}
}

/*
+----+------+----------+------+----------+

	|VER | ULEN | UNAME | PLEN | PASSWD |
	+----+------+----------+------+----------+
	| 1 | 1 | 1 to 255 | 1 | 1 to 255 |
	+----+------+----------+------+----------+
*/
func (s *TCPConn) resolveUserPwd(conn net.Conn) (user, pwd string, err error) {
	verByte := make([]byte, 1)
	n, err := conn.Read(verByte)
	if err != nil || n == 0 {
		return "", "", ERR_READ_USR_PWD
	}
	if uint(verByte[0]) != 1 {
		return "", "", ERR_READ_USR_PWD
	}
	ulenByte := make([]byte, 1)
	n, err = conn.Read(ulenByte)
	if err != nil || n == 0 {
		return "", "", ERR_READ_USR_PWD
	}
	if uint(ulenByte[0]) < 1 {
		return "", "", ERR_READ_USR_PWD
	}
	unameByte := make([]byte, uint(ulenByte[0]))
	n, err = conn.Read(unameByte)
	if err != nil || n == 0 {
		return "", "", ERR_READ_USR_PWD
	}
	user = string(unameByte)

	plen := make([]byte, 1)
	n, err = conn.Read(plen)
	if err != nil || n == 0 {
		return "", "", ERR_READ_USR_PWD
	}
	if uint(plen[0]) < 1 {
		return "", "", ERR_READ_USR_PWD
	}
	passwdByte := make([]byte, uint(plen[0]))
	n, err = conn.Read(passwdByte)
	if err != nil || n == 0 {
		return "", "", ERR_READ_USR_PWD
	}
	pwd = string(passwdByte)
	return user, pwd, nil
}
func (s *TCPConn) resolveAddress(conn net.Conn, req *TCPRequest) (err error) {
	//address types
	var IP net.IP
	switch req.atyp {
	case int(atypIPV4):
		log.Printf("[ID:%v]ADDRESS TYPE: IP V4 address <- %v\n", s.ID(), conn.RemoteAddr())
		dstAddrBytes := make([]byte, 4)
		_, err := conn.Read(dstAddrBytes)
		if err != nil {
			return err
		}
		IP = net.IP(dstAddrBytes)
	case int(atypFQDN):
		log.Printf("[ID:%v]ADDRESS TYPE: DOMAINNAME <- %v\n", s.ID(), conn.RemoteAddr())
		hostLenByte := make([]byte, 1)
		_, err := conn.Read(hostLenByte)
		if err != nil {
			return err
		}
		hostBytes := make([]byte, int(hostLenByte[0]))
		_, err = conn.Read(hostBytes)
		if err != nil {
			return err
		}
		domain := string(hostBytes)
		// IPAddrs, err := s.server.hostResolver.LookupIPAddr(context.Background(), domain)
		IPAddrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), domain)
		if err != nil {
			return err
		}
		IP = IPAddrs[0].IP
	case int(atypIPV6):
		log.Printf("[ID:%v]ADDRESS TYPE: IP V6 address <- %v\n", s.ID(), conn.RemoteAddr())
		dstAddrBytes := make([]byte, 16)
		_, err := conn.Read(dstAddrBytes)
		if err != nil {
			return err
		}
		IP = net.IP(dstAddrBytes)
	default:
		return ERR_ADDRESS_TYPE
	}
	dstPortBytes := make([]byte, 2)
	_, err = conn.Read(dstPortBytes)
	if err != nil {
		return err
	}
	dstPort := int(dstPortBytes[0])<<8 + int(dstPortBytes[1])
	req.TargetAddr = &net.TCPAddr{
		IP:   IP,
		Port: dstPort,
		Zone: "",
	}
	return
}
