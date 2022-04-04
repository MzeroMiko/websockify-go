package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/net/websocket"
)

func main() {
	help := flag.Bool("help", false, "")
	bindaddr := flag.String("bindaddr", "[::]:60000", "The address to bind to, [host]:port")
	backaddr := flag.String("backaddr", "127.0.0.1:60000", "The backend server address, [scheme://][host]:port")
	usetls := flag.Bool("tls", false, "Whether to use TLS in http or novnc")
	crtfile := flag.String("crt", "simp.crt", "cert pem for tls")
	keyfile := flag.String("key", "simp.key", "key pem for tls")
	novncprefix := flag.String("novncprefix", "/vnc", "prefix for noVNC/vnc.html")
	novncroot := flag.String("novncroot", "./noVNC", "root path for noVNC/")
	vncmagic := flag.String("vncmagic", "RFB", "magic number for vnc")
	flag.Parse()
	if *help {
		flag.Usage()
	} else {
		fmt.Printf("%s\nproxy ( pid : %d ) starts at \"%s\"\n", time.Now(), os.Getpid(), *bindaddr)
		NewNoVNCProxy(map[string]interface{}{
			"bindaddr": *bindaddr, "backaddr": *backaddr,
			"tls": *usetls, "crtfile": *crtfile, "keyfile": *keyfile,
			"novncprefix": *novncprefix, "novncroot": *novncroot, "vncmagic": *vncmagic,
		}).(*NoVNCProxy).Call()
	}
}

func genCert() ([]byte, []byte) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, max)
	subject := pkix.Name{
		Organization:       []string{"Example"},
		OrganizationalUnit: []string{"Example"},
		CommonName:         "Example",
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	pk, _ := rsa.GenerateKey(rand.Reader, 2048)
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &pk.PublicKey, pk) //DER 格式
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	key := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)})
	return cert, key
}

type NoVNCProxy struct {
	bindaddr, backaddr     string // bindaddr/backaddr: [host]:port
	tls                    bool
	crtfile, keyfile       string
	novncprefix, novncroot string
	vncmagic               []byte // []byte("RFB")
}

func NewNoVNCProxy(ins map[string]interface{}) interface{} {
	var instance = NoVNCProxy{
		bindaddr:    "[::]:60000",
		backaddr:    "127.0.0.1:9090",
		tls:         false,
		crtfile:     "simp.crt",
		keyfile:     "simp.crt",
		novncprefix: "/vnc",
		novncroot:   "./novnc",
		vncmagic:    []byte("RFB"),
	}
	if tmp, ok := ins["bindaddr"].(string); ok {
		instance.bindaddr = tmp
	}
	if tmp, ok := ins["backaddr"].(string); ok {
		instance.backaddr = tmp
	}
	if tmp, ok := ins["tls"].(bool); ok {
		instance.tls = tmp
	}
	if tmp, ok := ins["crtfile"].(string); ok {
		instance.crtfile = tmp
	}
	if tmp, ok := ins["keyfile"].(string); ok {
		instance.keyfile = tmp
	}
	if tmp, ok := ins["novncprefix"].(string); ok {
		instance.novncprefix = tmp
	}
	if tmp, ok := ins["novncroot"].(string); ok {
		instance.novncroot = tmp
	}
	if tmp, ok := ins["vncmagic"].([]byte); ok {
		instance.vncmagic = tmp
	}
	return &instance
}

func (vpxy NoVNCProxy) wsProxyHandler(addr string) websocket.Handler {
	return func(ws *websocket.Conn) {
		magic := vpxy.vncmagic
		lenmagic := len(magic)
		checked := false
		checkInd := 0

		conn, err := net.Dial("tcp", addr)
		if err != nil {
			ws.Close()
			return
		}
		ws.PayloadType = websocket.BinaryFrame

		tcp2ws := func(close chan error) {
			from := conn
			to := ws

			buffer := make([]byte, 4096)
			for {
				nfrom, err := from.Read(buffer)
				if err != nil {
					close <- err
					return
				} else if !checked && nfrom > 0 {
					for i := 0; i < nfrom; i++ {
						if ind := checkInd + i; ind < lenmagic {
							if buffer[i] != magic[i] {
								close <- fmt.Errorf("MAGIC: %s CHECK FAILED", string(magic))
								return
							}
						} else {
							checked = true
						}
					}
				}
				nto, err := to.Write(buffer[:nfrom])
				if err != nil || nto != nfrom {
					close <- err
					return
				}
			}

		}

		ws2tcp := func(close chan error) {
			from := ws
			to := conn

			buffer := make([]byte, 4096)
			for {
				nfrom, err := from.Read(buffer)
				if err != nil {
					close <- err
					return
				}
				nto, err := to.Write(buffer[:nfrom])
				if err != nil || nto != nfrom {
					close <- err
					return
				}
			}

		}

		close := make(chan error)
		go ws2tcp(close)
		go tcp2ws(close)
		err = <-close
		if err != nil && err.Error() != "EOF" {
			fmt.Println("ws-tcp error:", err)
		}

		conn.Close()
		ws.Close()
		<-close
	}
}

func (vpxy NoVNCProxy) Call() {
	usetls := vpxy.tls
	crtfile := vpxy.crtfile
	keyfile := vpxy.keyfile
	bindaddr := vpxy.bindaddr
	backaddr := vpxy.backaddr
	novncroot := vpxy.novncroot
	novncprefix := vpxy.novncprefix
	wsProxyHandler := vpxy.wsProxyHandler

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_prefix := strings.Trim(novncprefix, "/")
		srcPath := strings.TrimLeft(r.URL.Path, "/")
		if srcPath == _prefix || strings.Index(srcPath, _prefix+"/") == 0 {
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("X-Target-Addr", backaddr)
			websocket.Server{
				Handshake: func(config *websocket.Config, r *http.Request) error {
					if r.Header.Get("Sec-WebSocket-Protocol") != "" {
						config.Protocol = []string{"binary"}
					}
					r.Header.Set("Access-Control-Allow-Origin", "*")
					r.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")
					return nil
				},
				Handler: wsProxyHandler(backaddr),
			}.ServeHTTP(w, r)
		} else {
			http.FileServer(http.Dir(novncroot)).ServeHTTP(w, r)
		}
	})

	if usetls {
		_, errCrt := os.Stat(crtfile)
		_, errKey := os.Stat(keyfile)
		if !(errCrt == nil || os.IsExist(errCrt)) || !(errKey == nil || os.IsExist(errKey)) {
			cert, key := genCert()
			pair, _ := tls.X509KeyPair(cert, key)
			srv := http.Server{
				Addr:    bindaddr,
				Handler: nil,
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{pair},
				},
			}
			if err := srv.ListenAndServeTLS("", ""); err != nil {
				panic("ListenAndServeTLS: " + err.Error())
			}
		} else {
			if err := http.ListenAndServeTLS(bindaddr, crtfile, keyfile, nil); err != nil {
				panic("ListenAndServeTLS: " + err.Error())
			}
		}
	} else {
		if err := http.ListenAndServe(bindaddr, nil); err != nil {
			panic("ListenAndServe: " + err.Error())
		}
	}
}
