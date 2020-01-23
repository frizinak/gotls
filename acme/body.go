package acme

import (
	"strconv"
)

type directory struct {
	NewReg   string `json:"newAccount"`
	NewAuthz string `json:"newOrder"`
	NewNonce string `json:"newNonce"`
}

type registration struct {
	Contact   []string `json:"contact"`
	Agreement bool     `json:"termsOfServiceAgreed"`
}

type authIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type authorization struct {
	Identifiers []authIdentifier `json:"identifiers"`
}

type challenge struct {
	Type             string `json:"type"`
	KeyAuthorization string `json:"keyAuthorization"`
}

type cert struct {
	CSR string `json:"csr"`
}

type response interface {
	setHeader(key, value string)
}

type registrationResponse struct {
	Location string `json:"-"` // from Location header
}

func (r *registrationResponse) setHeader(key, value string) {
	if key == "Location" {
		r.Location = value
	}
}

type authChallenge struct {
	Type       string `json:"type"`
	Status     string `json:"status"`
	URI        string `json:"url"`
	Token      string `json:"token"`
	RetryAfter int    `json:"-"`
}

func (a *authChallenge) setHeader(key, value string) {
	if key == "Retry-After" {
		a.RetryAfter, _ = strconv.Atoi(value)
	}
}

type challengeResponse struct {
	Challenges []authChallenge `json:"challenges"`
}

func (r *challengeResponse) setHeader(key, value string) {
}

type authorizationResponse struct {
	Status         string   `json:"status"`
	Authorizations []string `json:"authorizations"`
	Finalize       string   `json:"finalize"`
	Certificate    string   `json:"certificate"`
	Location       string   `json:"-"` // from Location header
}

func (a *authorizationResponse) setHeader(key, value string) {
	if key == "Location" {
		a.Location = value
	}
}
