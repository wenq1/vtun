package kcp

import (
	"crypto/sha1"
	"io"
	"log"
	"net"
	"time"

	"github.com/net-byte/vtun/common/cache"
	"github.com/net-byte/vtun/common/cipher"
	"github.com/net-byte/vtun/common/config"
	"github.com/net-byte/vtun/tun"
	"github.com/songgao/water"
	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

// Start kcp client
func StartClient(config config.Config) {
	log.Printf("vtun kcp client started on %v", config.LocalAddr)
	iface := tun.CreateTun(config)
	go tunToKcp(config, iface)
	key := pbkdf2.Key([]byte(config.Key), []byte("vtun@2022"), 1024, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(key)
	for {
		conn, err := kcp.DialWithOptions(config.ServerAddr, block, 10, 3)
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		conn.SetWindowSize(10240, 10240)
		if err := conn.SetReadBuffer(4194304); err != nil {
			continue
		}
		cache.GetCache().Set("kcpconn", conn, 24*time.Hour)
		kcpToTun(config, conn, iface)
		cache.GetCache().Delete("kcpconn")
	}
}

func tunToKcp(config config.Config, iface *water.Interface) {
	packet := make([]byte, config.MTU)
	for {
		n, err := iface.Read(packet)
		if err != nil || n == 0 {
			continue
		}
		if v, ok := cache.GetCache().Get("kcpconn"); ok {
			b := packet[:n]
			if config.Obfs {
				b = cipher.XOR(b)
			}
			kcpconn := v.(net.Conn)
			kcpconn.SetWriteDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
			_, err = kcpconn.Write(b)
			if err != nil {
				continue
			}
		}
	}
}

func kcpToTun(config config.Config, kcpconn net.Conn, iface *water.Interface) {
	defer kcpconn.Close()
	packet := make([]byte, config.MTU)
	for {
		kcpconn.SetReadDeadline(time.Now().Add(time.Duration(config.Timeout) * time.Second))
		n, err := kcpconn.Read(packet)
		if err != nil || err == io.EOF {
			break
		}
		b := packet[:n]
		if config.Obfs {
			b = cipher.XOR(b)
		}
		_, err = iface.Write(b)
		if err != nil {
			break
		}
	}
}
