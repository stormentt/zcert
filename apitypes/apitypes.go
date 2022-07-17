package apitypes

import "github.com/stormentt/zcert/certs"

type SignCertReq struct {
	CSR    string          `json:"csr"`
	Params certs.CSRParams `json:"params"`
}
