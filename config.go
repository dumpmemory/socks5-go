package socks5

import (
	"log"
	"os"
	"regexp"
	"strconv"
)

// Implement yourself  Config , default is provided.
type Config interface {
	GetPort() string //server listen port
	HasAuth() bool   //auth status (noAuth or user/pwd)
	Socks5Auth       //authenticate user
}

type defConfig struct {
	Port string
	*defAuth
	hasAuth bool
	Addr    string
	// configPath string
}

var DefaultConfig = newDefConfig()

// default config ,read port ,user,pwd from argumens
func newDefConfig() *defConfig {
	s := &defConfig{
		defAuth: &defAuth{},
	}
	s.Port = "1080"
	c, _ := regexp.Compile(`^[0-9]+$`)
	if len(os.Args) == 2 {
		if c.MatchString(os.Args[1]) {
			s.Port = os.Args[1]
		}
	}
	if len(os.Args) == 4 {
		if c.MatchString(os.Args[1]) {
			s.Port = os.Args[1]
		}
		s.defAuth = &defAuth{userInfo: make(map[string]string)}
		s.defAuth.userInfo[os.Args[2]] = os.Args[3]
		s.hasAuth = true
	}
	return s
}
func (s *defConfig) GetPort() string {
	return s.Port
}
func (s *defConfig) HasAuth() bool {
	return s.hasAuth
}
func (s *defConfig) SetPort(p string) {
	if p == "0" {
		log.Printf("port error: %v", 0)
		return
	}
	if _, err := strconv.ParseInt(p, 10, 32); err != nil {
		log.Printf("port error: %v", err)
		return
	}
	s.Port = p
}
func (s *defConfig) SetAuth(users map[string]string) {
	s.defAuth.userInfo = make(map[string]string, 10)
	for key, value := range users {
		s.defAuth.userInfo[key] = value
	}
}
func (s *defConfig) SetAddr(ip string) {
	if ip == "" {
		return
	}
	s.Addr = ip
}
