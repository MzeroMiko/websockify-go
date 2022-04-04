# wsnovnc

a simple websockify implementation in go

# USAGE:
```bash
Usage of ./wsnovnc:
  -backaddr string
        The backend server address, [scheme://][host]:port (default "127.0.0.1:60000")
  -bindaddr string
        The address to bind to, [host]:port (default "[::]:60000")
  -crt string
        cert pem for tls (default "simp.crt")
  -help
    
  -key string
        key pem for tls (default "simp.key")
  -novncprefix string
        prefix for noVNC/vnc.html (default "/vnc")
  -novncroot string
        root path for noVNC/ (default "./noVNC")
  -tls
        Whether to use TLS in http or novnc
  -vncmagic string
        magic number for vnc (default "RFB")
 ```
 
 # build
 ```bash
 go env -w GO111MODULE=auto && go env -w GOPROXY=https://goproxy.cn && go build --ldflags '-w -s' wsnovnc.go && upx wsnovnc
 ```
 
 # Examples
 ```bash
/novnc/wsnovnc --tls -novncprefix /websockify -novncroot /novnc/noVNC -bindaddr [::]:8000 -backaddr 127.0.0.1:5900 > /tmp/novnc.log 2>&1 &
 ...
 ```
 # Thanks
 Thanks to https://github.com/pgaskin/easy-novnc, I learnt a lot from it to handle noVNC   
 Thanks to https://github.com/novnc/noVNC, a great web VNC 
 
 
 
 
 
 
