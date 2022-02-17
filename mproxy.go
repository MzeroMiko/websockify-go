package main

import (
	"fmt"
    "flag"
	"io"
	// "io/ioutil"
    "net"
	"net/url"
    "net/http"
	"net/http/httputil" 
	"os"
	"time"
	// "path"
	// "path/filepath"
	"strings"
	// "strconv"
	// "crypto/md5"
	"crypto/tls"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "crypto/rsa"
	// "encoding/json" // var must be Capital Letter start to json.Marshal !!!
	// "encoding/hex"
    "encoding/pem"
	"math/big"
	"golang.org/x/net/websocket"
)

func main() {
    protocal := flag.String("protocal", "", "protocal to proxy, [novnc | tcp | http]")
    bindaddr := flag.String("bindaddr", "[::]:60000", "The address to bind to, [host]:port")
    backaddr := flag.String("backaddr", "127.0.0.1:60000", "The backend server address, [scheme://][host]:port")
	usetls := flag.Bool("tls", false, "Whether to use TLS in http or novnc")
	crtfile := flag.String("crt", "simp.crt", "cert pem for tls")
	keyfile := flag.String("key", "simp.key", "key pem for tls")
	novncprefix := flag.String("novncprefix", "/vnc", "prefix for noVNC/vnc.html")
	novncroot := flag.String("novncroot", "./noVNC", "root path for noVNC/")
	vncmagic := flag.String("vncmagic", "RFB", "magic number for vnc")
    flag.Parse()
	fmt.Printf("%s\nproxy ( pid : %d ) starts at \"%s\"\n", time.Now(), os.Getpid(), *bindaddr)

	switch *protocal {
	case "tcp":
		NewTCPProxy(map[string]interface{}{
			"bindaddr": *bindaddr, "backaddr": *backaddr,
		}).(*TCPProxy).Call()
	case "http":
		NewHttpProxy(map[string]interface{}{
			"bindaddr": *bindaddr, "backaddr": *backaddr, 
			"tls": *usetls, "crtfile": *crtfile, "keyfile": *keyfile,
		}).(*HttpProxy).Call()
	case "novnc":
		NewNoVNCProxy(map[string]interface{}{
			"bindaddr": *bindaddr, "backaddr": *backaddr,
			"tls": *usetls, "crtfile": *crtfile, "keyfile": *keyfile,
			"novncprefix": *novncprefix, "novncroot": *novncroot, "vncmagic": *vncmagic,
		}).(*NoVNCProxy).Call()
	default:
		flag.Usage()
	}

}

func genCert() ([]byte, []byte) {
    max := new(big.Int).Lsh(big.NewInt(1),128)
    serialNumber, _ := rand.Int(rand.Reader, max)
    subject := pkix.Name{
        Organization:       []string{"Example"},
        OrganizationalUnit: []string{"Example"},
        CommonName:         "Example",
    }
    template := x509.Certificate{
        SerialNumber:   serialNumber,
        Subject:        subject,
        NotBefore:      time.Now(),
        NotAfter:       time.Now().Add(365 * 24 *time.Hour),
        KeyUsage:       x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature, 
        ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
    }
    pk, _ := rsa.GenerateKey(rand.Reader, 2048)  
    derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &pk.PublicKey, pk) //DER 格式
    cert := pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE", Bytes: derBytes})
    key := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)})
    return cert, key
}

// ------------------------------ TCPProcy ---------------------------- //
type TCPProxy struct {
	bindaddr, backaddr string // bindaddr/backaddr: [host]:port
}

func NewTCPProxy(ins map[string]interface{}) interface{} {
	var instance = TCPProxy{
		bindaddr: "[::]:60000", 
		backaddr: "127.0.0.1:9090",
	}
	if tmp, ok := ins["bindaddr"].(string); ok {
		instance.bindaddr = tmp
	}
	if tmp, ok := ins["backaddr"].(string); ok {
		instance.backaddr = tmp
	}
	return &instance
}

func (this TCPProxy) tcpProxyHandler(conn net.Conn, backaddr string) {
    tcpSend := func (from net.Conn, to net.Conn, close chan bool) {
		buffer := make([]byte, 4096)
		for {
			nfrom, err := from.Read(buffer)
			if err != nil {
				close <- true
				return
			}
			nto, err := to.Write(buffer[:nfrom])
			if err != nil || nto != nfrom {
				close <- true	
				return
			}
		}
	}

	target, err := net.Dial("tcp", backaddr)
    defer conn.Close()
    if err != nil {
		panic("tcp " + backaddr + " listen error:" + err.Error())
	} else {
        defer target.Close()
        close := make(chan bool, 2)
        go tcpSend(conn, target, close)
        go tcpSend(target, conn, close)
        <-close
    }
}

func (this TCPProxy) Call() {
	bindaddr := this.bindaddr
	backaddr := this.backaddr
	tcpProxyHandler := this.tcpProxyHandler

    if tcp, err := net.Listen("tcp", bindaddr); err == nil {
        defer tcp.Close()
        for {
            conn, err := tcp.Accept()
            if err != nil {
                panic("tcp accept listen error:" + err.Error())
            } else {
                go tcpProxyHandler(conn, backaddr)
            }
        }
    } else {
		panic("tcp " + bindaddr + " listen error:" + err.Error())
	}
}

// ------------------------------ HttpProcy ---------------------------- //
type HttpProxy struct {
    bindaddr, backaddr string // bindaddr/backaddr: [host]:port
	tls bool; crtfile, keyfile string
}

func NewHttpProxy(ins map[string]interface{}) interface{} {
	var instance = HttpProxy{
		bindaddr: "[::]:60000", 
		backaddr: "127.0.0.1:9090",
		tls: false,
		crtfile: "simp.crt",
		keyfile: "simp.crt",
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
	return &instance
}

func (this HttpProxy) Call() {
	usetls := this.tls
	crtfile := this.crtfile
	keyfile := this.keyfile
	bindaddr := this.bindaddr
	backaddr := this.backaddr

	http.HandleFunc("/", func(Response http.ResponseWriter, Request *http.Request) {
        // fmt.Println(Request)
		// prefix should be like /a
        u, _ := url.Parse(backaddr)
        Request.URL.Host = u.Host
        Request.URL.Scheme = u.Scheme
        // prefix = strings.TrimRight(prefix, "/")
        // Request.URL.Path = strings.TrimPrefix(Request.URL.Path, prefix)
        // if Request.URL.Path == "" {
            // Request.URL.Path = "/"
        // }
        // Request.Header.Set("X-Forwarded-Host", Request.Header.Get("Host"))
        Request.Host = u.Host
        proxy := httputil.NewSingleHostReverseProxy(u)
        proxy.Transport = &http.Transport {
            Proxy: nil,
            DialContext: (&net.Dialer{ Timeout: 30*time.Second, KeepAlive: 30*time.Second }).DialContext,
            MaxIdleConns: 100,
            IdleConnTimeout: 90 * time.Second,
            TLSHandshakeTimeout: 10 * time.Second,
            ExpectContinueTimeout: 1 * time.Second,
            TLSClientConfig: &tls.Config { InsecureSkipVerify: true, },
            DisableCompression: true,
        }
        proxy.ModifyResponse = func(res *http.Response) error {
            if (res.Header.Get("X-Frame-Options") != "") {
                res.Header.Del("X-Frame-Options")
            }
            if (res.Header.Get("cross-origin-resource-policy") != "") {
                res.Header.Del("cross-origin-resource-policy")
            }
            return nil
        }
		proxy.ServeHTTP(Response, Request)
 	})
	if usetls {
		_, errCrt := os.Stat(crtfile)
		_, errKey := os.Stat(keyfile)
		if !(errCrt == nil || os.IsExist(errCrt)) || !(errKey == nil || os.IsExist(errKey))  {
			cert, key := genCert()
			c, _ := os.Create(crtfile)
			k, _ := os.Create(keyfile)
			defer c.Close()
			defer k.Close()
			c.WriteString(string(cert))
			k.WriteString(string(key))
		}
		if err := http.ListenAndServeTLS(bindaddr, crtfile, keyfile, nil); err != nil {
			panic("ListenAndServeTLS: " + err.Error())
		}
	} else {
		if err := http.ListenAndServe(bindaddr, nil); err != nil {
			panic("ListenAndServe: " + err.Error())
		}
	}
}

// ------------------------------ NoVNCProxy ---------------------------- //
type NoVNCProxy struct {
    bindaddr, backaddr string // bindaddr/backaddr: [host]:port
	tls bool; crtfile, keyfile string
	novncprefix, novncroot string; vncmagic []byte // []byte("RFB")
}

func NewNoVNCProxy(ins map[string]interface{}) interface{} {
	var instance = NoVNCProxy{
		bindaddr: "[::]:60000", 
		backaddr: "127.0.0.1:9090",
		tls: false,
		crtfile: "simp.crt",
		keyfile: "simp.crt",
		novncprefix: "/vnc",
		novncroot: "./novnc",
		vncmagic: []byte("RFB"),
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

type mReader struct {
	reader io.Reader
	magic, check []byte   // []byte("RFB"); check magic
	remain int; fail bool // remain unchecked byte. check fail
}

// to implement the interface io.Reader; copy from https://github.com/pgaskin/easy-novnc
func (this *mReader) Read(buf []byte) (n int, err error) {
	if this.fail {
		return 0, io.EOF
	}
	n, err = this.reader.Read(buf)
	if err == nil && n > 0 && this.remain > 0 {
		this.remain -= copy(this.check[len(this.magic) - this.remain:], buf[:n])
		for i := 0; i < len(this.magic) - this.remain; i++ {
			if this.check[i] != this.magic[i] {
				this.fail = true
				return 0, io.EOF
			}
		}
	}
	return n, err
}

func (this NoVNCProxy) newReader(r io.Reader) *mReader {
	return &mReader{
		reader: r,
		magic: this.vncmagic, 
		check: make([]byte, len(this.vncmagic)),
		remain: len(this.vncmagic),
		fail: false,
	}
}

// copy from https://github.com/pgaskin/easy-novnc
func (this NoVNCProxy) wsProxyHandler(addr string) websocket.Handler {
	newReader := this.newReader
	return func(ws *websocket.Conn) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			ws.Close()
			return
		}
		ws.PayloadType = websocket.BinaryFrame
		reader := newReader(conn)
		send := func (dst io.Writer, src io.Reader, done chan error) {
			_, err := io.Copy(dst, src)
			// if err != nil {
			// 	fmt.Println("------------")
			// 	fmt.Println("tcp: ", conn)
			// 	fmt.Println("ws: ", ws)
			// 	fmt.Println("reader: ", reader)
			// 	fmt.Println("src: ", src)
			// 	fmt.Println("dst: ", dst)
			// 	fmt.Println("err: ", err)
			// 	fmt.Println("------------")
			// }
			done <- err
		}
		
		done := make(chan error)
		go send(conn, ws, done)
		go send(ws, reader, done)
		<-done
		if reader.fail {
			fmt.Printf("connect to vnc failed, get %#v\n", string(reader.check))
		} 
		conn.Close()
		ws.Close()
		<-done
	}
}

func (this NoVNCProxy) Call() {
	usetls := this.tls
	crtfile := this.crtfile
	keyfile := this.keyfile
	bindaddr := this.bindaddr
	backaddr := this.backaddr
	novncroot := this.novncroot
	novncprefix := this.novncprefix
	wsProxyHandler := this.wsProxyHandler

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_prefix := strings.Trim(novncprefix, "/")
		srcPath := strings.TrimLeft(r.URL.Path, "/")
		if srcPath == _prefix || strings.Index(srcPath, _prefix + "/") == 0 {
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("X-Target-Addr", backaddr)
			websocket.Server{
				Handshake: func (config *websocket.Config, r *http.Request) error {
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
		if !(errCrt == nil || os.IsExist(errCrt)) || !(errKey == nil || os.IsExist(errKey))  {
			cert, key := genCert()
			c, _ := os.Create(crtfile)
			k, _ := os.Create(keyfile)
			defer c.Close()
			defer k.Close()
			c.WriteString(string(cert))
			k.WriteString(string(key))
		}
		if err := http.ListenAndServeTLS(bindaddr, crtfile, keyfile, nil); err != nil {
			panic("ListenAndServeTLS: " + err.Error())
		}
	} else {
		if err := http.ListenAndServe(bindaddr, nil); err != nil {
			panic("ListenAndServe: " + err.Error())
		}
	}
}

