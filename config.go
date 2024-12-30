package socks5

import (
	"fmt"
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

const helpText = `
Usage: socks5-proxy [OPTIONS]

Options:
  <port>                    Listen port (default: 1080)
  <username> <password>     Enable authentication with username and password
  --help                    Show this help message

Environment variables:
  SOCKS5_PORT              Listen port
  SOCKS5_USER              Username for authentication
  SOCKS5_PASSWORD          Password for authentication

Examples:
  socks5-proxy                     # Run with default port 1080
  socks5-proxy 2080                # Run on port 2080
  socks5-proxy 1080 user pass      # Run with authentication
`

// default config ,read port ,user,pwd from argumens
func newDefConfig() *defConfig {
	// 检查是否为帮助命令
	if len(os.Args) == 2 && os.Args[1] == "--help" {
		fmt.Print(helpText)
		os.Exit(0)
	}

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

	// 从环境变量读取端口
	if envPort := os.Getenv("SOCKS5_PORT"); envPort != "" {
		s.Port = envPort
	}

	// 从环境变量读取认证信息
	if username := os.Getenv("SOCKS5_USER"); username != "" {
		if password := os.Getenv("SOCKS5_PASSWORD"); password != "" {
			s.defAuth = &defAuth{userInfo: make(map[string]string)}
			s.defAuth.userInfo[username] = password
			s.hasAuth = true
		}
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
