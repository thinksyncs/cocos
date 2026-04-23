// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package internaltransport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ultravioletrs/cocos/pkg/atls/ea"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "internal-transport"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

func TestServerAllowsIdentityWithoutTLSConfig(t *testing.T) {
	cert := selfSignedCert(t)
	a, b := net.Pipe()

	serverTLS := tls.Server(a, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	clientTLS := tls.Client(b, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})

	type result struct {
		conn *Conn
		err  error
	}
	serverCh := make(chan result, 1)
	clientCh := make(chan result, 1)

	go func() {
		conn, err := Server(serverTLS, &ServerConfig{
			Identity: cert,
		})
		serverCh <- result{conn: conn, err: err}
	}()

	go func() {
		conn, err := Client(clientTLS, &ClientConfig{
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
			},
		})
		clientCh <- result{conn: conn, err: err}
	}()

	srvRes := <-serverCh
	cliRes := <-clientCh

	if srvRes.err != nil {
		t.Fatalf("server failed: %v", srvRes.err)
	}
	if cliRes.err != nil {
		t.Fatalf("client failed: %v", cliRes.err)
	}

	defer srvRes.conn.Close()
	defer cliRes.conn.Close()
}

func TestClientDefaultsToSessionTracking(t *testing.T) {
	cert := selfSignedCert(t)
	sigExt, err := ea.SignatureAlgorithmsExtension([]uint16{uint16(tls.ECDSAWithP256AndSHA256)})
	if err != nil {
		t.Fatal(err)
	}
	req := &ea.AuthenticatorRequest{
		Type:    ea.HandshakeTypeClientCertificateRequest,
		Context: []byte("fixed-client-context"),
		Extensions: []ea.Extension{
			sigExt,
		},
	}

	clientCfg := &ClientConfig{
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		},
		Request: req,
	}

	runRoundTrip := func(serverCfg *ServerConfig) error {
		a, b := net.Pipe()
		serverTLS := tls.Server(a, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
		})
		clientTLS := tls.Client(b, clientCfg.TLSConfig.Clone())

		errCh := make(chan error, 2)
		go func() {
			defer serverTLS.Close()
			conn, err := Server(serverTLS, serverCfg)
			if conn != nil {
				defer conn.Close()
			}
			errCh <- err
		}()
		go func() {
			defer clientTLS.Close()
			conn, err := Client(clientTLS, clientCfg)
			if conn != nil {
				defer conn.Close()
			}
			errCh <- err
		}()

		var clientErr error
		for i := 0; i < 2; i++ {
			err := <-errCh
			if err == ea.ErrContextReuse {
				clientErr = err
			}
		}
		return clientErr
	}

	if err := runRoundTrip(&ServerConfig{Identity: cert}); err != nil {
		t.Fatalf("first round trip failed: %v", err)
	}
	if err := runRoundTrip(&ServerConfig{Identity: cert}); err != ea.ErrContextReuse {
		t.Fatalf("got %v, want %v", err, ea.ErrContextReuse)
	}
}

func TestServerDefaultsToSessionTracking(t *testing.T) {
	cert := selfSignedCert(t)
	sigExt, err := ea.SignatureAlgorithmsExtension([]uint16{uint16(tls.ECDSAWithP256AndSHA256)})
	if err != nil {
		t.Fatal(err)
	}
	req := &ea.AuthenticatorRequest{
		Type:    ea.HandshakeTypeClientCertificateRequest,
		Context: []byte("fixed-server-context"),
		Extensions: []ea.Extension{
			sigExt,
		},
	}

	serverCfg := &ServerConfig{Identity: cert}

	runRoundTrip := func(clientCfg *ClientConfig) error {
		a, b := net.Pipe()
		serverTLS := tls.Server(a, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
		})
		clientTLS := tls.Client(b, clientCfg.TLSConfig.Clone())

		errCh := make(chan error, 2)
		go func() {
			defer serverTLS.Close()
			conn, err := Server(serverTLS, serverCfg)
			if conn != nil {
				defer conn.Close()
			}
			errCh <- err
		}()
		go func() {
			defer clientTLS.Close()
			conn, err := Client(clientTLS, clientCfg)
			if conn != nil {
				defer conn.Close()
			}
			errCh <- err
		}()

		var serverErr error
		for i := 0; i < 2; i++ {
			err := <-errCh
			if err == ea.ErrContextReuse {
				serverErr = err
			}
		}
		return serverErr
	}

	clientCfg1 := &ClientConfig{
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		},
		Request: req,
	}
	if err := runRoundTrip(clientCfg1); err != nil {
		t.Fatalf("first round trip failed: %v", err)
	}

	clientCfg2 := &ClientConfig{
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
		},
		Request: req,
	}
	if err := runRoundTrip(clientCfg2); err != ea.ErrContextReuse {
		t.Fatalf("got %v, want %v", err, ea.ErrContextReuse)
	}
}
