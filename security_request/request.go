package security_request

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
)

const (
	MaxPayloadSize = 1000 * 1000
)

type rpmControls struct {
	Client         *http.Client
	GzipWriterPool *sync.Pool
}

type rpmRequest struct {
	Name string
	Data []byte
}

func SendRequest(cmd rpmRequest, cs rpmControls) *rpmResponse {
	return sendRequestInternal(cmd, cs)
}

func sendRequestInternal(cmd rpmRequest, cs rpmControls) *rpmResponse {
	url := csecURL(cmd)
	compressed, err := compress(cmd.Data, cs.GzipWriterPool)
	if nil != err {
		return newRPMResponse(err)
	}

	if l := compressed.Len(); l > MaxPayloadSize {
		return newRPMResponse(fmt.Errorf("Payload size for %s too large: %d greater than %d", cmd.Name, l, MaxPayloadSize))
	}

	req, err := http.NewRequest("POST", url.String(), compressed)
	if nil != err {
		return newRPMResponse(err)
	}

	req.Header = getConnectionHeader() //set all csec herader

	resp, err := cs.Client.Do(req)
	if err != nil {
		return newRPMResponse(err)
	}
	r := newRPMResponse(nil)

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		r.SetError(err)
	} else {
		r.AddBody(body)
	}

	return r
}

// utils
func csecURL(cmd rpmRequest) url.URL {
	var u url.URL

	u.Host = "localhost:8080"
	u.Scheme = "https"

	// update this
	switch cmd.Name {
	case "1":
		u.Path = "sendEvent"
	case "2":
		u.Path = "sendHC"
	}

	u.RawQuery = getPueryParam()
	return u
}

func compress(b []byte, gzipWriterPool *sync.Pool) (*bytes.Buffer, error) {
	w := gzipWriterPool.Get().(*gzip.Writer)
	defer gzipWriterPool.Put(w)

	var buf bytes.Buffer
	w.Reset(&buf)
	_, err := w.Write(b)
	w.Close()

	if nil != err {
		return nil, err
	}

	return &buf, nil
}

func getConnectionHeader() http.Header {
	connectionHeader := http.Header{}
	return connectionHeader
}

func getPueryParam() string {
	query := url.Values{}
	return query.Encode()
}
