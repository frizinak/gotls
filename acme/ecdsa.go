package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path"
)

func GenerateECDSAKey(filepath string, curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	dirname := path.Dir(filepath)

	if err := os.MkdirAll(dirname, 0755); err != nil {
		return nil, err
	}

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	marsh, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(filepath, marsh, 0600)

	return priv, err
}

func LoadOrGenerateECDSAKey(paths []string, curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	if len(paths) == 0 {
		return nil, errors.New("paths can not be empty")
	}

	key, err := LoadECDSAKey(paths)
	if err == errNotExists {
		return GenerateECDSAKey(paths[0], curve)
	}

	return key, err
}

func LoadECDSAKey(paths []string) (*ecdsa.PrivateKey, error) {
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

		key, err := x509.ParseECPrivateKey(raw)
		if err == nil {
			return key, err
		}

		// Try to decode as PEM
		block, _ := pem.Decode(raw)
		if block == nil {
			return key, err
		}

		return x509.ParseECPrivateKey(block.Bytes)
	}

	return nil, errNotExists
}
