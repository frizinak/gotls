package acme

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

// CertificateCallback may be used to communicate
// certificate updates and errors back to the caller of Certify
type CertificateCallback func(*tls.Certificate, error)

// Certify is the all-in-one, very opinionated, wrapper around the acme Client.
//
// It will:
//
// - try to load a certificate from cacheFile.
//
// - renew the certificate after refreshTime since certificate.NotBefore.
//
// - call the given CertificateCallback with the new certificate.
//
// when no certificate could be loaded from the cache file
// or the file is unrelated to the provided tlsKey
// or certificate.DNSNames != domain, it will:
//
// - Try to register / login to the acme api
//
// - Request authorization challenges for the given domains
//
// - Complete the challenges using the simpleHTTP method using the given mux
//
// - Send a Certificate Signing Request and call the given CertificateCallback
func Certify(
	log *log.Logger,
	// ACME api directory uri
	// (e.g.: "https://acme-staging.api.letsencrypt.org/directory")
	directory string,
	// list of domains,
	// first one will be used as subject name (i.e.: common name)
	domains []string,
	// acme contact info (e.g.: "email:info@company.com")
	contact []string,
	refreshTimeout time.Duration,
	accountKey *rsa.PrivateKey,
	tlsKey *ecdsa.PrivateKey,
	serveMux *http.ServeMux,
	cacheFile string,
	callback CertificateCallback,
) (chan bool, error) {
	stop := make(chan bool)

	if len(domains) == 0 {
		return stop, errors.New("Can't certify 0 domains")
	}

	c, err := NewClient(directory, accountKey)
	if err != nil {
		return stop, err
	}

	var certificate *ocspCertificate
	var timeout time.Duration
	ocspTimeout := time.Millisecond * 200
	refreshOCSPTimeout := time.Hour * 1
	errOCSPTimeout := time.Second * 10

	hasValidCert := false
	derPriv, err := x509.MarshalECPrivateKey(tlsKey)
	if err != nil {
		return stop, err
	}
	stat, err := os.Stat(cacheFile)
	if err == nil || !os.IsNotExist(err) {
		// File exists, should be file and be readable.
		if stat.IsDir() {
			return stop, errors.New("The provided cache file is a directory")
		}

		cache, err := ioutil.ReadFile(cacheFile)
		if err != nil {
			return stop, err
		}

		cachedCert, err := x509.ParseCertificate(cache)
		if err != nil {
			return stop, err
		}

		forceNewCert := false
		for _, dns := range domains {
			found := false
			for _, dnsCache := range cachedCert.DNSNames {
				if dns == dnsCache {
					found = true
					break
				}
			}

			if !found {
				forceNewCert = true
				break
			}
		}

		log.Println("Found cached certificate")
		if forceNewCert {
			log.Println("But new domains were requested")
		}

		expires := cachedCert.NotBefore.Add(refreshTimeout)
		certificate, err = c.der2ocsp([][]byte{cache}, derPriv)

		hasValidCert = !forceNewCert && err == nil
		now := time.Now()
		if hasValidCert && expires.After(now) {
			var cert *tls.Certificate
			if certificate != nil {
				cert = certificate.Certificate
			}

			callback(cert, err)
			if err == nil {
				diff := expires.Sub(now)
				log.Printf("Waiting for expiry (in %s)", diff.String())
				timeout = diff
			}
		}
	}

	c.Handle(serveMux)
	waitIssue := time.After(timeout)
	waitOCSP := time.After(ocspTimeout)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-waitIssue:
				timeout = refreshTimeout
				certificate, err = issue(c, log, domains, contact, tlsKey, derPriv, cacheFile)
				var cert *tls.Certificate
				if certificate != nil {
					cert = certificate.Certificate
				}
				callback(cert, err)
				waitIssue = time.After(timeout)
			case <-waitOCSP:
				if certificate == nil {
					continue
				}
				ocspTimeout = refreshOCSPTimeout

				if err := certificate.update(); err != nil {
					ocspTimeout = errOCSPTimeout
					log.Printf("FAILED TO UPDATE OCSPStaple: %s", err.Error())
				}
				waitOCSP = time.After(ocspTimeout)
			}
		}
	}()

	return stop, nil
}

func issue(
	c *Client,
	log *log.Logger,
	domains []string,
	contact []string,
	tlsKey *ecdsa.PrivateKey,
	derPriv []byte,
	cacheFile string,
) (*ocspCertificate, error) {
	c.resetState()
	err := c.Register(contact)
	if err != nil {
		return nil, err
	}

	log.Println("Registered / authenticated")
	for _, domain := range domains {
		challenges, err := c.Authorize(domain)
		if err != nil {
			return nil, err
		}
		log.Println("Requested challenge(s)")

		for _, c := range challenges {
			if err := c.Create(); err != nil {
				return nil, err
			}
		}

		log.Println("Responded to challenge(s)")
		for _, c := range challenges {
			if err := <-c.Poll(); err != nil {
				return nil, fmt.Errorf("%s: Poll failed with err: %+v\n", domain, err)
			}
		}

		log.Println("Beaten challenge(s)")
	}
	csr, err := GenerateCSR(tlsKey, domains[0], domains[1:])
	if err != nil {
		return nil, err
	}

	certPEMBytes, err := c.Cert(csr)
	if err != nil {
		return nil, err
	}
	pem, _ := pem.Decode(certPEMBytes)
	if pem == nil {
		return nil, errors.New("acme certificate could not be PEM decoded")
	}
	certBytes := pem.Bytes

	certificate, err := c.der2ocsp([][]byte{certBytes}, derPriv)
	if err == nil {
		log.Println("New/renewed certificate")
		if err := ioutil.WriteFile(cacheFile, certBytes, 0644); err != nil {
			log.Printf("FAILED TO WRITE CERTIFICATE: %s", err.Error())
		}
	}

	return certificate, err
}
