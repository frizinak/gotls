package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path"
)

var errNotExists = errors.New("key does not exist")

// GenerateRSAKey generates and saves a rsa private key to filepath.
// Creating directories as needed.
func GenerateRSAKey(filepath string, bits int) (*rsa.PrivateKey, error) {
	dirname := path.Dir(filepath)

	if err := os.MkdirAll(dirname, 0755); err != nil {
		return nil, err
	}

	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	marsh := x509.MarshalPKCS1PrivateKey(priv)
	err = ioutil.WriteFile(filepath, marsh, 0600)

	return priv, err
}

// LoadOrGenerateRSAKey loads the first file that exists
// in paths as an rsa private key.
// If none were found a new key will be generated and saved to the first
// filepath in paths.
func LoadOrGenerateRSAKey(paths []string, bits int) (*rsa.PrivateKey, error) {
	if len(paths) == 0 {
		return nil, errors.New("paths can not be empty")
	}

	key, err := LoadRSAKey(paths)
	if err == errNotExists {
		return GenerateRSAKey(paths[0], bits)
	}

	return key, err
}

func LoadRSAKey(paths []string) (*rsa.PrivateKey, error) {
	for i := range paths {
		f, err := os.Open(paths[i])
		if err != nil {
			continue
		}

		defer f.Close()
		raw, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, err
		}

		key, err := x509.ParsePKCS1PrivateKey(raw)
		if err == nil {
			return key, err
		}

		// Try to decode as PEM
		block, _ := pem.Decode(raw)
		if block == nil {
			return key, err
		}
		if block.Type != "RSA PRIVATE KEY" {
			return key, err
		}

		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	return nil, errNotExists
}

// GenerateCSR returns a Certificate Signing Request
func GenerateCSR(priv interface{}, main string, san []string) ([]byte, error) {
	tpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: main},
		DNSNames: san,
	}

	return x509.CreateCertificateRequest(rand.Reader, tpl, priv)
}
