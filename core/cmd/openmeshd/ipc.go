package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	ipcCommandStatus = "status"
	ipcCommandPeers  = "peers"
	ipcCommandStop   = "stop"
)

type ipcRequest struct {
	Command string `json:"command"`
}

type ipcResponse struct {
	Error   string        `json:"error,omitempty"`
	Message string        `json:"message,omitempty"`
	Status  *daemonStatus `json:"status,omitempty"`
	Peers   []daemonPeer  `json:"peers,omitempty"`
}

type ipcServer struct {
	listener net.Listener
	handler  func(ipcRequest) ipcResponse

	closeOnce sync.Once
	wg        sync.WaitGroup
}

func newIPCServer(endpoint string, handler func(ipcRequest) ipcResponse) (*ipcServer, error) {
	listener, err := listenIPC(endpoint)
	if err != nil {
		return nil, err
	}

	return &ipcServer{
		listener: listener,
		handler:  handler,
	}, nil
}

func (s *ipcServer) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		s.wg.Add(1)
		go func(conn net.Conn) {
			defer s.wg.Done()
			defer conn.Close()

			var request ipcRequest
			if err := json.NewDecoder(conn).Decode(&request); err != nil {
				_ = json.NewEncoder(conn).Encode(ipcResponse{Error: fmt.Sprintf("invalid request: %v", err)})
				return
			}

			response := s.handler(request)
			_ = json.NewEncoder(conn).Encode(response)
		}(conn)
	}
}

func (s *ipcServer) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		closeErr = s.listener.Close()
		s.wg.Wait()
		_ = cleanupIPCEndpoint(s.listener.Addr().String())
	})
	return closeErr
}

func sendIPCRequest(endpoint string, request ipcRequest, timeout time.Duration) (ipcResponse, error) {
	conn, err := dialIPC(endpoint, timeout)
	if err != nil {
		return ipcResponse{}, err
	}
	defer conn.Close()

	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return ipcResponse{}, err
	}

	var response ipcResponse
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return ipcResponse{}, err
	}
	return response, nil
}
