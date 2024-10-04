package security_request

import (
	"errors"
	"net/url"
)

type rpmResponse struct {
	statusCode int
	body       []byte
	err        error
}

func (resp *rpmResponse) SetError(err error) {
	resp.err = err

}

func (resp *rpmResponse) AddBody(body []byte) {
	resp.body = body

}
func (resp rpmResponse) GetError() error {
	return resp.err
}

func newRPMResponse(err error) *rpmResponse {
	if err == nil {
		return &rpmResponse{}
	}

	// remove url from errors to avoid sensitive data leaks
	var ue *url.Error
	if errors.As(err, &ue) {
		ue.URL = "**REDACTED-URL**"
	}

	return &rpmResponse{
		err: err,
	}
}
