package healthcheck

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCA struct {
	cert     *x509.Certificate
	certPool *x509.CertPool
	privKey  *rsa.PrivateKey
}

type serverKeys struct {
	cert *tls.Certificate
}

func generateTestCA() (*testCA, error) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{"FAKE CA FOR TESTING ONLY"},
			Country:      []string{"US"},
			Locality:     []string{"Anytown"},
		},
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(10 * time.Minute),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("testCA: generateTestCA: could not generate private key: %w", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, privKey.Public(), privKey)
	if err != nil {
		return nil, fmt.Errorf("testCA: generateTestCA: could not create CA certificate: %w", err)
	}

	var caPEM bytes.Buffer
	pem.Encode(&caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM(caPEM.Bytes())
	if !ok {
		return nil, fmt.Errorf("testCA: generateTestCA: could not generate cert pool")
	}

	return &testCA{
		cert:     cert,
		certPool: pool,
		privKey:  privKey,
	}, nil
}

func (ca *testCA) generateClientTLSConfig() *tls.Config {
	return &tls.Config{
		RootCAs: ca.certPool,
	}
}

func (ca *testCA) generateCertificates(hostname string) (*serverKeys, error) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			Organization: []string{fmt.Sprintf("TEST CERTIFICATE: %s", hostname)},
		},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(1 * time.Minute),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{hostname},
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("testCA: generateCertificates: could not generate private key: %w", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.cert, privKey.Public(), ca.privKey)
	if err != nil {
		return nil, fmt.Errorf("testCA: generateCertificates: could not generate certificate: %w", err)
	}

	var certPEMBytes bytes.Buffer
	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	pem.Encode(&certPEMBytes, certPEM)

	var privKeyPEMBytes bytes.Buffer
	privKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}
	pem.Encode(&privKeyPEMBytes, privKeyPEM)

	serverCert, err := tls.X509KeyPair(certPEMBytes.Bytes(), privKeyPEMBytes.Bytes())
	if err != nil {
		return nil, fmt.Errorf("testCA: generateCertificates: could not encode key pair: %w", err)
	}

	return &serverKeys{
		cert: &serverCert,
	}, nil

}

func (sk *serverKeys) generateServerTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*sk.cert},
	}
}

func TestCheckHealth(t *testing.T) {
	t.Run("basic case (200)", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/", r.URL.Path)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		err := CheckHealth(srv.URL, 5*time.Second, false)
		assert.NoError(t, err)
	})

	t.Run("basic case (302)", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/", r.URL.Path)
			w.WriteHeader(http.StatusFound)
		}))
		defer srv.Close()

		err := CheckHealth(srv.URL, 5*time.Second, false)
		assert.NoError(t, err)
	})

	t.Run("base case (200) w/ TLS", func(t *testing.T) {
		ca, err := generateTestCA()
		require.NoError(t, err)
		localhostCert, err := ca.generateCertificates("localhost")
		require.NoError(t, err)

		called := false

		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		srv.TLS = localhostCert.generateServerTLSConfig()
		srv.StartTLS()
		defer srv.Close()

		client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: ca.generateClientTLSConfig(),
			},
		}

		t.Cleanup(func() {
			client = &http.Client{}
		})

		err = CheckHealth(srv.URL, 5*time.Second, false)
		assert.NoError(t, err)

		assert.True(t, called)
	})

	t.Run("fail test if bad cert and we haven't told to ignore", func(t *testing.T) {
		called := false
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		srv.StartTLS()
		defer srv.Close()

		err := CheckHealth(srv.URL, 5*time.Second, false)
		assert.Error(t, err)
		assert.False(t, called)
	})

	t.Run("ignore bad cert if we need to", func(t *testing.T) {
		called := false
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		srv.StartTLS()
		defer srv.Close()

		err := CheckHealth(srv.URL, 5*time.Second, true)
		assert.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("handle timeout", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(3 * time.Second)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		err := CheckHealth(srv.URL, 1*time.Second, false)
		assert.Error(t, err)
	})
}
