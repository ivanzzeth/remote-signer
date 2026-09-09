package notify

import (
	"encoding/json"
	"io"
	"net/http"
)

// roundTripFunc implements http.RoundTripper using a plain function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// newJSONResponse builds an *http.Response with the given status and JSON body.
func newJSONResponse(status int, v interface{}) *http.Response {
	body, _ := json.Marshal(v)
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytesReader(body)),
	}
}

// bytesReader wraps a byte slice into a reader for use in http.Response.Body.
func bytesReader(b []byte) io.Reader {
	return &byteReadCloser{data: b}
}

type byteReadCloser struct {
	data []byte
	off  int
}

func (r *byteReadCloser) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}
