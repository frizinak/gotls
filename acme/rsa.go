package acme

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
)

// GenerateCSR returns a Certificate Signing Request
func GenerateCSR(priv interface{}, main string, san []string) ([]byte, error) {
	tpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: main},
		DNSNames: san,
	}

	return x509.CreateCertificateRequest(rand.Reader, tpl, priv)
}
