package acme

import (
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	statusPending = "pending"
	statusValid   = "valid"
	statusReady   = "ready"
)

// Challenge represents an acme simpleHTTP challenge
// which can be created (acknowledged)
// and polled for its status
type Challenge struct {
	challengeURI string
	authzURI     string
	token        string
	challenge    challenge
	c            *Client
}

func (c *Challenge) Write(w io.Writer) error {
	_, err := w.Write([]byte(c.challenge.KeyAuthorization))
	return err
}

// Create posts an acknowledge to the acme api
func (c *Challenge) Create() error {
	resp := &authorizationResponse{}
	status, err := c.c.post(c.challengeURI, c.challenge, resp)
	if err != nil {
		return err
	}

	if status != 200 {
		return fmt.Errorf("Invalid response with status %d: %+v", status, resp)
	}

	return nil
}

// Poll the challenge status.
// Puts an error on the returned channel if something went wrong or
// nil if everything went as expected
func (c *Challenge) Poll() <-chan error {
	var timeout = 2 * time.Second
	chn := make(chan error, 1)
	go func() {
		defer c.c.removeChallenge(c)
		for {
			resp := &authChallenge{}
			status, err := c.c.post(c.authzURI, nil, resp)
			if status != 202 && status != 200 {
				chn <- fmt.Errorf("Received status code %d: %+v", status, resp)
				return
			}

			if err != nil {
				chn <- err
				return
			}

			switch resp.Status {
			case statusReady:
				fallthrough
			case statusValid:
				chn <- nil
				return
			case statusPending:
				// retry
			default:
				chn <- errors.New(resp.Status)
				return
			}

			timeout = 1
			if resp.RetryAfter != 0 {
				timeout = time.Duration(resp.RetryAfter) * time.Second
			}

			<-time.After(timeout)
		}
	}()

	return chn
}
