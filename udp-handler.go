package socks5

import (
	"bytes"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

//AssembleHeader assemble data with header
/*
	+----+------+------+----------+----------+----------+
	 |RSV | FRAG | ATYP | DST.ADDR | DST.PORT | DATA |
	 +----+------+------+----------+----------+----------+
	 | 2 | 1 | 1 | Variable | 2 | Variable |
	 +----+------+------+----------+----------+----------+*/
func AssembleHeader(data []byte, addr *net.UDPAddr) *bytes.Buffer {
	proxyData := bytes.NewBuffer(nil)
	if addr == nil {
		return nil
	}
	addrATYP := byte(0)
	var addrBody []byte
	switch {
	case addr.IP == nil:
		addrATYP = atypIPV4
		addrBody = []byte{0, 0, 0, 0}
	case addr.IP.To4() != nil:
		addrATYP = atypIPV4
		addrBody = []byte(addr.IP.To4())
	case addr.IP.To16() != nil:
		addrATYP = atypIPV6
		addrBody = []byte(addr.IP.To16())
	default:
		log.Printf("failed to format address")
		return nil
	}
	proxyData.Write([]byte{0, 0, 0, addrATYP})
	proxyData.Write(addrBody)
	proxyData.Write([]byte{byte(addr.Port >> 8)})
	proxyData.Write([]byte{byte(addr.Port & 0xff)})
	proxyData.Write(data)
	return proxyData
}

//TrimHeader trim socks5 header to send exact data to remote
/*
	+----+------+------+----------+----------+----------+
	 |RSV | FRAG | ATYP | DST.ADDR | DST.PORT | DATA |
	 +----+------+------+----------+----------+----------+
	 | 2 | 1 | 1 | Variable | 2 | Variable |
	 +----+------+------+----------+----------+----------+*/
func TrimHeader(dataBuf *bytes.Buffer) (frag byte, dstIP *net.IP, dstPort int) {
	// Each UDP datagram carries a UDP request   header with it:

	//RSV
	dataBuf.ReadByte()
	//FRAG
	frag, err := dataBuf.ReadByte()
	if err != nil {
		return
	}
	//ATYP
	atyp, err := dataBuf.ReadByte()
	if err != nil {
		return
	}
	switch int(atyp) {
	case int(atypIPV4):
		//ipv4
		b := make([]byte, 4)
		_, err = dataBuf.Read(b)
		if err != nil {
			return
		}
		d := net.IP(b)
		dstIP = &d
	case int(atypFQDN):
		//domain name
		b := make([]byte, 1)
		_, err = dataBuf.Read(b)
		if err != nil {
			return
		}
		domainNameBytes := make([]byte, int(b[0]))
		_, err = dataBuf.Read(domainNameBytes)
		if err != nil {
			return
		}
		addrs, err := net.LookupHost(string(domainNameBytes))
		if err != nil {
			return
		}
		ipAddr, err := net.ResolveIPAddr("tcp", addrs[0])
		if err != nil {
			return
		}
		dstIP = &ipAddr.IP
	case int(atypIPV6):
		//ipv6
		b := make([]byte, 16)
		_, err = dataBuf.Read(b)
		if err != nil {
			return
		}
		d := net.IP(b)
		dstIP = &d
	default:
		return
	}
	b := make([]byte, 2)
	_, err = dataBuf.Read(b)
	if err != nil {
		return
	}
	dstPort = int(b[0])<<8 + int(b[1])
	//log.Printf("dstIP:%v dstPort:%v\n", dstIP, dstPort)
	return
}

func (s *Server) handleUDPReplie(relayConn *net.UDPConn, request *UDPRequest, done chan struct{}) {
	b := make([]byte, MAXUDPDATA)
	request.remoteConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	close(done)
	for {
		n, _, err := request.remoteConn.ReadFromUDP(b)
		if n > 0 {
			dataBuf := AssembleHeader(b[:n], request.remoteAddr)
			relayConn.WriteMsgUDP(dataBuf.Bytes(), nil, request.clientAddr)
			log.Printf("[UDP] remote:%v -> client:%v, bytes:%d\n", request.remoteAddr, request.clientAddr, n)
		} else if err != nil {
			if err == io.EOF ||
				strings.Contains(err.Error(), "timeout") ||
				strings.Contains(err.Error(), "closed") {
				break
			}
		}
	}
	s.locker.Lock()
	request.remoteConn.Close()
	delete(s.UDPRequestMap, request.clientAddr.String())
	s.locker.Unlock()
}
func (s *Server) processUDPDategrams(request *UDPRequest, dataBuf *bytes.Buffer, frag byte, b []byte, remoteConn *net.UDPConn) {
	switch {
	//data was fragmented,save data into queue
	case int(frag) > request.position:
		request.position = int(frag)
		request.reassemblyQueue = append(request.reassemblyQueue, dataBuf.Bytes()...)

	case frag == 0:
		if len(request.reassemblyQueue) > 0 {
			remoteConn.Write(request.reassemblyQueue)
			request.reassemblyQueue = []byte{}
			request.position = 0
		}
		remoteConn.Write(dataBuf.Bytes())
		log.Printf("[UDP] client:%v -> remote:%v, bytes:%d\n", request.clientAddr, remoteConn.RemoteAddr(), len(b))
	case int(frag) < request.position:
		log.Printf("[UDP] Ignoring outdated or duplicate fragment from client:%v\n", request.clientAddr)
		request.reassemblyQueue = []byte{}
		request.position = 0
	}
}

// UDPTransport handle UDP traffic
func (s *Server) UDPTransport(relayConn *net.UDPConn, clientAddr *net.UDPAddr, b []byte) {
	dataBuf := bytes.NewBuffer(b)
	frag, dstIP, dstPort := TrimHeader(dataBuf)
	remoteAddr := &net.UDPAddr{
		IP:   *dstIP,
		Port: dstPort,
		Zone: "",
	}
	//udp dial
	remoteConn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return
	}
	//if request is existed
	s.locker.Lock()
	request, exists := s.UDPRequestMap[clientAddr.String()]
	if !exists {
		request = &UDPRequest{
			clientAddr:      clientAddr,
			remoteConn:      remoteConn,
			remoteAddr:      remoteAddr,
			reassemblyQueue: []byte{},
			position:        0,
		}
		s.UDPRequestMap[clientAddr.String()] = request
	}
	s.locker.Unlock()
	//UDPRequestChan <- request
	LaunchReplyChan := make(chan struct{})
	//read remote data,transfer to client
	go s.handleUDPReplie(relayConn, request, LaunchReplyChan)
	<-LaunchReplyChan

	s.processUDPDategrams(request, dataBuf, frag, b, remoteConn)
}
