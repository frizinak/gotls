package acme_test

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/frizinak/gotls/acme"
)

func TestLoadECDSA(t *testing.T) {
	file := "/tmp/acme_test_ecdsa"
	filePem := file + ".pem"

	err := os.Remove(file)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	k, err := acme.LoadOrGenerateECDSAKey(
		[]string{file},
		elliptic.P256(),
	)
	if err != nil {
		t.Fatal(err)
	}

	m, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}

	b := &pem.Block{
		Type:  "lala",
		Bytes: m,
	}

	f, err := os.Create(filePem)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := pem.Encode(f, b); err != nil {
		t.Fatal(err)
	}

	k2, err := acme.LoadECDSAKey([]string{filePem})
	if err != nil {
		t.Fatal(err)
	}

	m2, err := x509.MarshalECPrivateKey(k2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(m, m2) {
		t.Error("Not equal")
	}
}
