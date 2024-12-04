package wireproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/sourcegraph/conc"
)

const proxyAuthHeaderKey = "Proxy-Authorization"

type HTTPServer struct {
	config *HTTPConfig

	auth CredentialValidator
	dial func(network, address string) (net.Conn, error)

	authRequired bool
	vtun         *VirtualTun
}

func (s *HTTPServer) authenticate(req *http.Request) (int, error) {
	if !s.authRequired {
		return 0, nil
	}

	auth := req.Header.Get(proxyAuthHeaderKey)
	if auth == "" {
		return http.StatusProxyAuthRequired, fmt.Errorf(http.StatusText(http.StatusProxyAuthRequired))
	}

	enc := strings.TrimPrefix(auth, "Basic ")
	str, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return http.StatusNotAcceptable, fmt.Errorf("decode username and password failed: %w", err)
	}
	pairs := bytes.SplitN(str, []byte(":"), 2)
	if len(pairs) != 2 {
		return http.StatusLengthRequired, fmt.Errorf("username and password format invalid")
	}
	if s.auth.Valid(string(pairs[0]), string(pairs[1])) {
		return 0, nil
	}
	return http.StatusUnauthorized, fmt.Errorf("username and password not matching")
}

func (s *HTTPServer) handleConn(req *http.Request, conn net.Conn, ctx context.Context) (peer net.Conn, err error) {
	addr := req.Host
	if !strings.Contains(addr, ":") {
		port := "443"
		addr = net.JoinHostPort(addr, port)
	}

	s.vtun.logger.Verbosef("Got HTTP Connect to %s", addr)
	peer, err = s.dial("tcp", addr)
	if err != nil {
		return peer, fmt.Errorf("tun tcp dial failed: %w", err)
	}

	_, err = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		_ = peer.Close()
		peer = nil
	}

	return
}

func (s *HTTPServer) handle(req *http.Request, ctx context.Context) (peer net.Conn, err error) {
	addr := req.Host
	if !strings.Contains(addr, ":") {
		port := "80"
		addr = net.JoinHostPort(addr, port)
	}

	s.vtun.logger.Verbosef("Got HTTP GET to %s", addr)
	peer, err = s.dial("tcp", addr)
	if err != nil {
		return peer, fmt.Errorf("tun tcp dial failed: %w", err)
	}

	err = req.Write(peer)
	if err != nil {
		_ = peer.Close()
		peer = nil
		return peer, fmt.Errorf("conn write failed: %w", err)
	}

	return
}

func (s *HTTPServer) serve(conn net.Conn, ctx context.Context) {
	var rd = bufio.NewReader(conn)
	req, err := http.ReadRequest(rd)
	if err != nil {
		s.vtun.logger.Errorf("read request failed: %s", err)
		return
	}

	code, err := s.authenticate(req)
	if err != nil {
		resp := responseWith(req, code)
		if code == http.StatusProxyAuthRequired {
			resp.Header.Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		}
		_ = resp.Write(conn)
		s.vtun.logger.Errorf("authenticate failed: %s", err)
		return
	}

	var peer net.Conn
	switch req.Method {
	case http.MethodConnect:
		peer, err = s.handleConn(req, conn, ctx)
	case http.MethodGet:
		peer, err = s.handle(req, ctx)
	default:
		_ = responseWith(req, http.StatusMethodNotAllowed).Write(conn)
		s.vtun.logger.Errorf("unsupported protocol: %s", req.Method)
		return
	}
	if err != nil {
		s.vtun.logger.Errorf("dial proxy failed: %s", err)
		return
	}
	if peer == nil {
		s.vtun.logger.Errorf("dial proxy failed: peer nil")
		return
	}
	go func() {
		wg := conc.NewWaitGroup()
		wg.Go(func() {
			_, err = io.Copy(conn, peer)
			_ = conn.Close()
		})
		wg.Go(func() {
			_, err = io.Copy(peer, conn)
			_ = peer.Close()
		})
		wg.Wait()
	}()
}

// ListenAndServe is used to create a listener and serve on it
func (s *HTTPServer) ListenAndServe(ctx context.Context, network, addr string) error {
	var lc net.ListenConfig
	// ctx, cancel := context.WithCancel(context.Background())
	server, err := lc.Listen(ctx, network, addr)
	if err != nil {
		s.vtun.logger.Errorf("listen tcp failed: %w", err)
	}
	defer func(server net.Listener) {
		_ = server.Close()
		s.vtun.logger.Verbosef("Proxy server closed")
	}(server)

	connChan := make(chan net.Conn)
	errChan := make(chan error, 1) // Make errChan buffered so it won't block

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				conn, err := server.Accept()
				if err != nil {
					select {
					case errChan <- err:
					case <-ctx.Done():
					}
					return
				}
				select {
				case connChan <- conn:
				case <-ctx.Done():
					_ = conn.Close()
					return
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			s.vtun.logger.Verbosef("Context cancelled, stopping server")
			return ctx.Err()
		case err := <-errChan:
			s.vtun.logger.Errorf("accept request failed: %w", err)
			return err
		case conn := <-connChan:
			go func(conn net.Conn) {
				s.serve(conn, ctx)
			}(conn)
		}
	}
}
