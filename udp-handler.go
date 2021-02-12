package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"time"
)

func AssemblyProxyHeader(data []byte, addr net.Addr) *bytes.Buffer {
	proxyData := bytes.NewBuffer(nil)
	udpAddr, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		return nil
	}
	addrATYP := byte(0)
	var addrBody []byte
	switch {
	case udpAddr.IP == nil:
		addrATYP = atypIPV4
		addrBody = []byte{0, 0, 0, 0}
	case udpAddr.IP.To4() != nil:
		addrATYP = atypIPV4
		addrBody = []byte(udpAddr.IP.To4())
	case udpAddr.IP.To16() != nil:
		addrATYP = atypIPV6
		addrBody = []byte(udpAddr.IP.To16())
	default:
		fmt.Errorf("failed to format address")
		return nil
	}
	proxyData.Write([]byte{0, 0, 0, addrATYP})
	proxyData.Write(addrBody)
	proxyData.Write([]byte{byte(udpAddr.Port >> 8)})
	proxyData.Write([]byte{byte(udpAddr.Port & 0xff)})
	proxyData.Write(data)
	return proxyData
}

//trim head
func TrimProxyHeader(dataBuf *bytes.Buffer) (frag byte, dstIP *net.IP, dstPort int) {
	// Each UDP datagram carries a UDP request   header with it:
	/*
		+----+------+------+----------+----------+----------+
		 |RSV | FRAG | ATYP | DST.ADDR | DST.PORT | DATA |
		 +----+------+------+----------+----------+----------+
		 | 2 | 1 | 1 | Variable | 2 | Variable |
		 +----+------+------+----------+----------+----------+*/
	//RSV
	dataBuf.ReadByte()
	dataBuf.ReadByte()
	//FRAG
	frag, err := dataBuf.ReadByte()
	if err != nil {
		return
	}
	//ATYP
	atyp, err := dataBuf.ReadByte()
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
	fmt.Printf("dstIP:%v dstPort:%v\n", dstIP, dstPort)
	return
}
func TransferUDPTraffic(relayConn *net.UDPConn, ctx context.Context) {
	reassemblyQueue := make([]byte, 0)
	position := 0 //1-127
	expires := time.Second * 5
	//create remote relayed UDP conn
	listenAddr := make(chan net.Addr)
	closeChan := make(chan struct{}, 2)

	// remote -> relay -> client
	go func() {
		for {
			select {
			case <-closeChan:
				return
			default:
				remoteRelayConn, err := net.ListenUDP("udp", (<-listenAddr).(*net.UDPAddr))
				if err != nil {
					return
				}
				//assemble proxy header
				b := make([]byte, MAXUDPDATA)
				n, _, err := remoteRelayConn.ReadFromUDP(b)
				if err != nil {
					//closeChan <- err
					return
				}
				dataBuf := bytes.NewBuffer(b[:n])
				bugWithHeader := AssemblyProxyHeader(dataBuf.Bytes(), relayConn.RemoteAddr())
				relayConn.Write(bugWithHeader.Bytes())
			}
		}
	}()

	// client -> relay -> remote
	go func() {
		for {
			select {
			case <-closeChan:
				return
			default:
				b := make([]byte, MAXUDPDATA)
				n, _, err := relayConn.ReadFromUDP(b)
				if err != nil {
					continue
				}
				dataBuf := bytes.NewBuffer(b[:n])
				frag, dstIP, dstPort := TrimProxyHeader(dataBuf)
				//drop any datagrams arriving from any source IP other than one recorded for the particular association.
				//todo

				if int(frag) > position {
					position = int(frag)
					//save data
					reassemblyQueue = append(reassemblyQueue, dataBuf.Bytes()...)
					continue
				}

				//udp dial
				remoteConn, err := net.DialUDP("udp", nil, &net.UDPAddr{
					IP:   *dstIP,
					Port: dstPort,
					Zone: "",
				})
				if err != nil {
					continue
				}
				listenAddr <- remoteConn.LocalAddr()

				//standalone
				if frag == 0 {
					if len(reassemblyQueue) > 0 {
						remoteConn.Write(reassemblyQueue)
						//reinitialize
						reassemblyQueue = make([]byte, 0)
						position = 0
						relayConn.SetReadDeadline(time.Time{})
					}
					remoteConn.Write(dataBuf.Bytes())
					continue
				}

				//begin to handle  a new datagrams
				if int(frag) < position {
					//send previous datagrams
					remoteConn.Write(reassemblyQueue)
					//reinitialize
					reassemblyQueue = make([]byte, 0)
					position = 0
					relayConn.SetReadDeadline(time.Time{})

					//set timeout
					err := relayConn.SetReadDeadline(time.Now().Add(expires))
					if err != nil {
						//closeChan <- err
						continue
					}
					//save data
					position = int(frag)
					//save data
					reassemblyQueue = append(reassemblyQueue, dataBuf.Bytes()...)
				}
			}
		}
	}()

	go func() {
		<-ctx.Done()
		closeChan <- struct{}{}
		closeChan <- struct{}{}
	}()
}
