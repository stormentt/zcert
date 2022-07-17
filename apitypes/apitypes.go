package apitypes

import (
	"time"

	"github.com/stormentt/zcert/certs"
)

type SecurityBlock struct {
	RequestTime time.Time `json:"request_time"`
	Nonce       string    `json:"nonce"`
}

type SignCertReq struct {
	CSR    string          `json:"csr"`
	Params certs.CSRParams `json:"params"`

	SecurityBlock
}
