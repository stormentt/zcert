package apitypes

import (
	"fmt"
	"time"

	"github.com/stormentt/zcert/certs"
)

const NonceLength = 32
const MaxRequestAge = time.Minute * 5

type NoNonceError struct{}
type InvalidNonceError struct{}

type NoRequestTimeError struct{}
type RequestTimeTooOldError struct {
	when time.Time
}

func (e *NoNonceError) Error() string {
	return "no nonce provided"
}

func (e *InvalidNonceError) Error() string {
	return fmt.Sprintf("invalid nonce provided. nonces must be %d characters long", NonceLength)
}

func (e *NoRequestTimeError) Error() string {
	return "no request_time provided"
}

func (e *RequestTimeTooOldError) Error() string {
	return fmt.Sprintf("request too old (%s)", e.when)
}

type SecurityBlock struct {
	RequestTime time.Time `json:"request_time"`
	Nonce       string    `json:"nonce"`
}

type SignCertReq struct {
	CSR    string          `json:"csr"`
	Params certs.CSRParams `json:"params"`

	SecurityBlock
}

func (scr SignCertReq) Validate() error {
	if scr.Nonce == "" {
		return &NoNonceError{}
	}

	if len(scr.Nonce) != NonceLength {
		return &InvalidNonceError{}
	}

	if scr.RequestTime.IsZero() {
		return &NoRequestTimeError{}
	}

	if time.Since(scr.RequestTime) > MaxRequestAge {
		return &RequestTimeTooOldError{when: scr.RequestTime}
	}

	return nil
}
