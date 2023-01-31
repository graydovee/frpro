package vhost

import (
	"crypto/tls"
	"github.com/fatedier/frp/pkg/transport"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/util"
	"net"
	"net/http"
	"sort"
	"sync"
)

type HttpsReverseProxyServer struct {
	Addr         string
	ReserveProxy *HTTPReverseProxy

	listener net.Listener
	crts     map[string][][2]string
	crtSet   map[[2]string]struct{}
	stop     <-chan struct{}
	mu       sync.Mutex
}

func (h *HttpsReverseProxyServer) NewTlsListener(addr string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	var tlsConfig *tls.Config
	var err error

	var certs []tls.Certificate

	for crt := range h.crtSet {
		cert, err := util.LoadX509KeyPair(crt[0], crt[1])
		if err != nil {
			log.Error("parse tls error", err)
			continue
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		log.Info("start http reverse proxy listen with insecure tls")
		tlsConfig, err = transport.NewServerTLSConfig("", "", "")
		tlsConfig.InsecureSkipVerify = true
	} else {
		log.Info("start http reverse proxy listen, cert num", len(certs))
		tlsConfig = &tls.Config{
			Certificates: certs,
		}
	}
	listen, err := tls.Listen("tcp", addr, tlsConfig)

	tls.InsecureCipherSuites()
	if err != nil {
		return err
	}
	h.listener = listen
	return nil
}

func (h *HttpsReverseProxyServer) RegisterTls(name, tlsCrt, tlsKey string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.crts == nil {
		h.crts = make(map[string][][2]string)
	}

	certs, err := util.SplitTlsCert(tlsCrt, tlsKey)
	if err != nil {
		log.Error("parse tls cert error", err)
		return
	}
	sort.Slice(certs, func(i, j int) bool {
		if certs[i][0] != certs[j][0] {
			return certs[i][0] < certs[j][0]
		}
		return certs[i][1] < certs[j][1]
	})
	h.crts[name] = certs

	newCrtSet := make(map[[2]string]struct{})
	for _, crts := range h.crts {
		for _, crt := range crts {
			newCrtSet[crt] = struct{}{}
		}
	}
	if CertsEqual(newCrtSet, h.crtSet) {
		log.Info("certs not updated, not restart listener")
		return
	}
	h.crtSet = newCrtSet

	if h.listener != nil {
		log.Info("tls update, listener restart")
		_ = h.listener.Close()
	}
}

func (h *HttpsReverseProxyServer) UnRegisterTls(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	delete(h.crts, name)
}

func (h *HttpsReverseProxyServer) Serve() {
	for {
		if err := h.NewTlsListener(h.Addr); err != nil {
			log.Error("https reverse proxy listen err", err)
			return
		}
		err := http.Serve(h.listener, h.ReserveProxy)
		select {
		case <-h.stop:
			return
		default:
			log.Info("tls listener closed, try reconnected soon after", err)
		}
	}
}

func CertsEqual(c1, c2 map[[2]string]struct{}) bool {
	if len(c1) != len(c2) {
		return false
	}
	for crt := range c1 {
		if _, ok := c2[crt]; ok {
			if !ok {
				return false
			}
		}
	}
	return true
}
