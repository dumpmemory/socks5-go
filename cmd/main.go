package main

import (
	"log"

	"github.com/realzhangliu/socks5-go"
)

func main() {
	//var config socks5.Config
	//Implement yourself  Config , default is provided.
	S5Server := socks5.NewSocks5Server(nil)
	log.Println(S5Server.Listen())
}
