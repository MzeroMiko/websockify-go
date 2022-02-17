# websockify-go | mproxy
a reverse proxy that support tcp, http, https, and the most important, noVNC, which makes it a websockify

# USAGE:
```bash
Usage of ./goserve/others/novnc/mproxy:
  -backaddr string
        The backend server address, [scheme://][host]:port (default "127.0.0.1:60000")
  -bindaddr string
        The address to bind to, [host]:port (default "[::]:60000")
  -crt string
        cert pem for tls (default "simp.crt")
  -key string
        key pem for tls (default "simp.key")
  -novncprefix string
        prefix for noVNC/vnc.html (default "/vnc")
  -novncroot string
        root path for noVNC/ (default "./noVNC")
  -protocal string
        protocal to proxy, [novnc | tcp | http]
  -tls
        Whether to use TLS in http or novnc
  -vncmagic string
        magic number for vnc (default "RFB")
 ```
 
 # build
 go env -w GO111MODULE=on
 go env -w GOPROXY=https://goproxy.cn
 go build --ldflags '-w -s' mproxy.go
 upx mproxy
 
 # Examples
 ```bash
 mproxy -protocal novnc -novncprefix /vnc -novncroot noVNC-1.3.0/ -bindaddr :8002 -backaddr 127.0.0.1:5900 >> mproxy.log 2>&1
 mproxy -protocal tcp -bindaddr :8002 -backaddr 127.0.0.1:22 >> mproxy.log 2>&1
 mproxy -protocal http -tls -bindaddr :8002 -backaddr https://127.0.0.1:9090 >> mproxy.log 2>&1
 mproxy -protocal http -bindaddr :8002 -backaddr https://127.0.0.1:9090 >> mproxy.log 2>&1
 ...
 ```
 # Thanks
 Thanks to https://github.com/pgaskin/easy-novnc, I learnt a lot from it to handle noVNC
 Thanks to https://github.com/novnc/noVNC, a great web VNC 
 
 
 
 
 
 
