package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestServeHTTPWaitsForActiveRequest(t *testing.T) {
	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &closeNotifyingListener{
		Listener: baseListener,
		closed:   make(chan struct{}),
	}
	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseHandler) })
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(handlerStarted)
		<-releaseHandler
		_, _ = io.WriteString(w, "complete")
	})}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		release()
		cancel()
		_ = server.Close()
	})
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- serveHTTP(ctx, server, listener, time.Second)
	}()

	requestDone := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://" + listener.Addr().String())
		if err != nil {
			requestDone <- err
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err == nil && string(body) != "complete" {
			err = fmt.Errorf("response body = %q", body)
		}
		requestDone <- err
	}()

	waitForSignal(t, handlerStarted, "handler start")
	cancel()
	waitForSignal(t, listener.closed, "listener close")
	select {
	case err := <-serveDone:
		t.Fatalf("serveHTTP returned before active handler completed: %v", err)
	default:
	}

	release()
	if err := waitForResult(t, requestDone, "request completion"); err != nil {
		t.Fatal(err)
	}
	if err := waitForResult(t, serveDone, "server shutdown"); err != nil {
		t.Fatalf("serveHTTP: %v", err)
	}
}

type closeNotifyingListener struct {
	net.Listener
	once   sync.Once
	closed chan struct{}
}

func (l *closeNotifyingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

func waitForSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func waitForResult(t *testing.T, result <-chan error, name string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
		return nil
	}
}
