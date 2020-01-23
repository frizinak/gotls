package acme

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"

	"gopkg.in/square/go-jose.v2"
)

var errNotPKIXCert = errors.New("not a pkix certificate")

// Client wraps acme api calls
type Client struct {
	m          sync.RWMutex
	thumbprint string
	accountURL string
	signingKey jose.SigningKey
	nonce      string
	dir        string
	endpoints  *directory
	challenges []*Challenge
	finalize   string
}

// NewClient returns a new acme Client.
func NewClient(dirURL string, accountKey *rsa.PrivateKey) (*Client, error) {
	dirURL = strings.TrimRight(dirURL, "/")

	thumb, err := (&jose.JSONWebKey{
		Key:       accountKey.Public().(*rsa.PublicKey),
		Algorithm: "RSA",
	}).Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}

	c := &Client{
		thumbprint: base64.RawURLEncoding.EncodeToString(thumb),
		dir:        dirURL,
		challenges: make([]*Challenge, 0),
		signingKey: jose.SigningKey{Algorithm: jose.RS256, Key: accountKey},
	}

	return c, nil
}

// Nonce returns the last nonce, exported to implement jose.NonceSource
func (c *Client) Nonce() (string, error) {
	if c.nonce == "" {
		if err := c.getDir(false); err != nil {
			return "", err
		}

		resp, err := http.DefaultClient.Head(c.endpoints.NewNonce)
		if err != nil {
			return "", err
		}

		c.setNonce(resp.Header.Get("Replay-Nonce"))
	}
	return c.nonce, nil
}

func (c *Client) setNonce(n string) {
	c.nonce = n
}

func (c *Client) resetState() {
	c.nonce = ""
	c.accountURL = ""
	c.endpoints = nil
}

// Handle attaches an http handle func to the given mux in order to complete
// simpleHTTP challenges.
func (c *Client) Handle(mux *http.ServeMux) {
	mux.HandleFunc(
		"/.well-known/acme-challenge/",
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Println("(todo remove)   RECEIVED REQ:", r.URL.Path)
			if len(c.challenges) == 0 {
				http.NotFound(w, r)
				return
			}

			uparts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			if len(uparts) != 3 {
				http.NotFound(w, r)
				return
			}

			c.m.RLock()
			defer c.m.RUnlock()
			for _, ch := range c.challenges {
				if uparts[2] != ch.token {
					continue
				}

				if err := ch.Write(w); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
				return
			}

			http.NotFound(w, r)
		},
	)
}

func (c *Client) removeChallenge(challenge *Challenge) {
	c.m.Lock()
	defer c.m.Unlock()
	index := -1
	for i, ch := range c.challenges {
		if ch == challenge {
			index = i
		}
	}
	if index == -1 {
		return
	}

	c.challenges[index] = c.challenges[len(c.challenges)-1]
	c.challenges[len(c.challenges)-1] = nil
	c.challenges = c.challenges[:len(c.challenges)-1]
}

func (c *Client) marshal(url string, msg interface{}) (string, error) {
	r := []byte{}
	if msg != nil {
		var err error
		r, err = json.Marshal(msg)
		if err != nil {
			return "", err
		}
	}
	return c.sign(url, r)
}

func (c *Client) getDir(force bool) error {
	if !force && c.endpoints != nil {
		return nil
	}

	resp, err := http.Get(c.dir)
	if err != nil {
		return err
	}

	d := json.NewDecoder(resp.Body)
	defer resp.Body.Close()

	dir := &directory{}
	if err := d.Decode(dir); err != nil {
		return err
	}

	c.endpoints = dir
	c.setNonce(resp.Header.Get("Replay-Nonce"))
	return nil
}

func (c *Client) der2ocsp(derCerts [][]byte, derKey []byte) (*ocspCertificate, error) {
	if len(derCerts) == 0 {
		return nil, errors.New("No certificate given")
	}

	derCert := derCerts[0]

	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: derKey}),
	)

	if err != nil {
		return nil, err
	}

	// Ignoring error as tls.X509KeyPair already validated the cert.
	pair.Leaf, _ = x509.ParseCertificate(derCert)
	if len(derCerts) == 1 {
		intermediates, err := c.fetchIntermediates(pair.Leaf)
		if err == errNotPKIXCert {
			err = nil
		}

		if err != nil {
			return nil, err
		}

		if len(intermediates) == 0 {
			return nil, errors.New("No intermediate certificate could be found/fetched")
		}

		derCerts = append(derCerts, intermediates...)
	}

	for i := 1; i < len(derCerts); i++ {
		derCert = derCerts[i]
		pair.Certificate = append(
			pair.Certificate,
			derCert,
		)
	}

	rawIssuer := derCerts[1]
	issuer, err := x509.ParseCertificate(rawIssuer)
	if err != nil {
		return nil, err
	}

	return &ocspCertificate{&pair, issuer}, nil
}

func (c *Client) fetchIntermediates(cert *x509.Certificate) (ints [][]byte, err error) {
	ints = make([][]byte, 0)
	if len(cert.IssuingCertificateURL) == 0 {
		return
	}

	for {
		cert, err = c.fetchIntermediate(cert)
		if err != nil {
			break
		}

		// Probably the root cert
		if len(cert.IssuingCertificateURL) == 0 {
			break
		}

		ints = append(ints, cert.Raw)
	}

	return
}

func (c *Client) fetchIntermediate(cert *x509.Certificate) (*x509.Certificate, error) {
	if len(cert.IssuingCertificateURL) == 0 {
		return nil, errors.New("No issuing certificate url")
	}

	resp, err := c.getWithResponse(
		cert.IssuingCertificateURL[0],
		"application/pkix-cert",
	)

	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return nil, err
	}

	if resp.Header.Get("Content-Type") != "application/pkix-cert" {
		return nil, errNotPKIXCert
	}

	der, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

func (c *Client) post(url string, msg interface{}, response response) (int, error) {
	resp, err := c.postWithResponse(url, msg)
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		if resp != nil {
			return resp.StatusCode, err
		}

		return 0, err
	}

	if response != nil {
		d := json.NewDecoder(resp.Body)
		if err := d.Decode(response); err != nil {
			return resp.StatusCode, err
		}

		for i := range resp.Header {
			for j := range resp.Header[i] {
				response.setHeader(i, resp.Header[i][j])
			}
		}
	}

	return resp.StatusCode, nil
}

func (c *Client) postWithResponse(url string, msg interface{}) (*http.Response, error) {
	signed, err := c.marshal(url, msg)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(signed))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/jose+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return resp, err
	}

	c.setNonce(resp.Header.Get("Replay-Nonce"))
	return resp, err
}

func (c *Client) getWithResponse(url string, accept string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return resp, err
	}

	c.setNonce(resp.Header.Get("Replay-Nonce"))
	return resp, err
}

func (c *Client) sign(url string, msg []byte) (string, error) {
	headers := map[jose.HeaderKey]interface{}{"url": url}
	if c.accountURL != "" {
		headers["kid"] = c.accountURL
	}
	signer, err := jose.NewSigner(
		c.signingKey,
		&jose.SignerOptions{
			NonceSource:  c,
			EmbedJWK:     c.accountURL == "",
			ExtraHeaders: headers,
		},
	)
	if err != nil {
		return "", err
	}

	r, err := signer.Sign(msg)
	if err != nil {
		return "", err
	}

	return r.FullSerialize(), nil
}

// Register tries to create a new acme account.
// If an account already exists or was successfully created,
// no error will be returned.
func (c *Client) Register(contact []string) error {
	if err := c.getDir(false); err != nil {
		return err
	}

	req := &registration{contact, true}
	resp := &registrationResponse{}
	status, err := c.post(c.endpoints.NewReg, req, resp)
	if err != nil {
		return err
	}

	c.accountURL = resp.Location
	if status == 200 || status == 201 {
		return nil
	}

	return fmt.Errorf("Failed to register with json: %+v", resp)
}

// Authorize sends an authorize request and returns a simpleHTTP challenge,
// which can be Created and Polled.
func (c *Client) Authorize(domain string) ([]*Challenge, error) {
	req := &authorization{
		[]authIdentifier{authIdentifier{Type: "dns", Value: domain}},
	}

	resp := &authorizationResponse{}
	if err := c.getDir(false); err != nil {
		return nil, err
	}

	status, err := c.post(c.endpoints.NewAuthz, req, resp)
	if err != nil {
		return nil, err
	}

	if status != 201 {
		return nil, fmt.Errorf("Failed to create auth request with json: %+v", resp)
	}

	c.finalize = resp.Finalize
	chs := make([]*Challenge, 0, 1)
	for _, i := range resp.Authorizations {
		cResp := &challengeResponse{}
		_, err := c.post(i, nil, cResp)
		if err != nil {
			return nil, err
		}
		for _, chall := range cResp.Challenges {
			if chall.Type == "http-01" {
				ch := &Challenge{
					challengeURI: chall.URI,
					authzURI:     resp.Location,
					token:        chall.Token,
					challenge: challenge{
						Type: "simpleHttp",
						KeyAuthorization: fmt.Sprintf(
							"%s.%s",
							chall.Token,
							c.thumbprint,
						),
					},
					c: c,
				}
				if err != nil {
					return nil, err
				}
				c.m.Lock()
				defer c.m.Unlock()
				c.challenges = append(c.challenges, ch)
				chs = append(chs, ch)
			}
		}
	}

	if len(chs) != 0 {
		return chs, nil
	}

	return nil, fmt.Errorf("No supported challenges found in: %+v", resp)
}

// Cert creates/renews a certificate by sending a Certificate Signing Request.
func (c *Client) Cert(csr []byte) (certificate []byte, err error) {
	if err := c.getDir(false); err != nil {
		return nil, err
	}

	csrBase64 := base64.RawURLEncoding.EncodeToString(csr)
	req := &cert{csrBase64}
	auth := &authorizationResponse{}
	_, err = c.post(c.finalize, req, auth)
	if err != nil {
		return nil, err
	}

	if auth.Certificate == "" {
		return nil, errors.New("empty certificate, not all challenges complete?")
	}

	resp, err := c.postWithResponse(auth.Certificate, nil)
	if err != nil {
		return nil, err
	}
	certificate, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 && resp.StatusCode != 201 && resp.StatusCode != 202 {
		return nil, fmt.Errorf("Invalid http status code: %d: %s", resp.StatusCode, string(certificate))
	}

	return certificate, err
}
