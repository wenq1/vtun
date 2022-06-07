package kcp

import (
	"crypto/sha1"
	"log"
	"time"

	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/common/netutil"
	"github.com/net-byte/vtun/tun"
	"github.com/songgao/water"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

//Start kcp server
func StartServer(config config.Config) {
	log.Printf("vtun kcp server started on %v", config.LocalAddr)
	iface := tun.CreateTun(config)
	key := pbkdf2.Key([]byte(config.Key), []byte("vtun@2022"), 1024, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(key)
	ln, err := kcp.ListenWithOptions(config.LocalAddr, block, 10, 3)
	if err != nil {
		log.Panic(err)
	}
	// server -> client
	go toClient(config, iface)
	// client -> server
	for {
		kcpconn, err := ln.AcceptKCP()
		if err != nil {
			continue
		}
		kcpconn.SetWindowSize(10240, 10240)
		if err := kcpconn.SetReadBuffer(4194304); err != nil {
			continue
		}
		go toServer(config, kcpconn, iface)
	}
}

func toClient(config config.Config, iface *water.Interface) {
	packet := make([]byte, config.MTU)
	for {
		n, err := iface.Read(packet)
		if err != nil || n == 0 {
			continue
		}
		b := packet[:n]
		if key := netutil.GetDstKey(b); key != "" {
			if v, ok := cache.GetCache().Get(key); ok {
				if config.Obfs {
					b = cipher.XOR(b)
				}
				v.(*kcp.UDPSession).Write(b)
			}
		}
	}
}

func toServer(config config.Config, kcpconn *kcp.UDPSession, iface *water.Interface) {
	defer kcpconn.Close()
	packet := make([]byte, config.MTU)
	for {
		kcpconn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
		n, err := kcpconn.Read(packet)
		if err != nil || n == 0 {
			break
		}
		b := packet[:n]
		if config.Obfs {
			b = cipher.XOR(b)
		}
		if key := netutil.GetSrcKey(b); key != "" {
			cache.GetCache().Set(key, kcpconn, 10*time.Minute)
			iface.Write(b)
		}
	}
}
