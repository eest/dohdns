// Package dohdns is a library for building DNS API Servers (DNS over HTTPS or "DOH").
package dohdns

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

const mime string = "application/dns-udpwireformat"

// Request is passed from the generic request handler to the a more specific
// handler.
type Request struct {
	W  http.ResponseWriter
	R  *http.Request
	DB Database
}

// Database is the interface used by the query handlers to look up
// results.
type Database interface {
	Query(data []byte) ([]byte, int, error)
}

// GetRequest handles GET requests.
type GetRequest struct {
	Request
}

// PostRequest handles POST requests.
type PostRequest struct {
	Request
}

// HandleRequest is a simple help wrapper around the GET and POST handlers.
func HandleRequest(database Database, log *log.Logger) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var err error

		switch r.Method {
		case http.MethodGet:
			req := &GetRequest{
				Request: Request{
					W:  w,
					R:  r,
					DB: database,
				},
			}
			err = req.Handle()
		case http.MethodPost:
			req := &PostRequest{
				Request: Request{
					W:  w,
					R:  r,
					DB: database,
				},
			}
			err = req.Handle()
		default:
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			err = fmt.Errorf("HandleRequest: only %s and %s methods are supported", http.MethodGet, http.MethodPost)
		}

		if log != nil {
			if err != nil {
				log.Printf("%s | %s", r.RemoteAddr, err)
			} else {
				log.Printf("%s | successful %s request", r.RemoteAddr, r.Method)
			}
		}
	}

}

// Handle does the necessary validation of a GET request and hands of
// the query to a backend.
func (req *GetRequest) Handle() error {

	req.W.Header().Set("Content-Type", mime)

	// 4.1.  DNS Wire Format:
	//
	// When using the GET method, the data payload MUST be encoded with
	// base64url [RFC4648] and then provided as a variable named "dns" to
	// the URI Template expansion.  Padding characters for base64url MUST
	// NOT be included.
	if dns, ok := req.R.URL.Query()["dns"]; ok {

		// 4.  The HTTP Request
		//
		// A DNS API client encodes a single DNS query into an HTTP
		// request [...]
		if len(dns) != 1 {
			http.Error(req.W, http.StatusText(http.StatusUnprocessableEntity), http.StatusUnprocessableEntity)
			return fmt.Errorf("%s: only 1 'dns' parameter is allowed", http.MethodGet)
		}

		// Stop processing if the parameter has no content.
		if len(dns[0]) == 0 {
			http.Error(req.W, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return fmt.Errorf("%s: 'dns' parameter is empty", http.MethodGet)
		}

		// Padding characters for base64url MUST NOT be included.
		// Unpadded base64url equals base64.RAWURLEncoding:
		qdata, err := base64.RawURLEncoding.DecodeString(dns[0])
		if err != nil {
			http.Error(req.W, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return err
		}

		rdata, httpStatus, err := req.DB.Query(qdata)

		if err != nil {
			http.Error(req.W, http.StatusText(httpStatus), httpStatus)
			return err
		}

		req.W.Write(rdata)

	} else {
		http.Error(req.W, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return fmt.Errorf("%s: no 'dns' parameter in request", http.MethodGet)
	}

	return nil
}

// Handle does the necessary validation of a POST request and hands of
// the query to a backend.
func (req *PostRequest) Handle() error {

	req.W.Header().Set("Content-Type", mime)

	// 4.1.  DNS Wire Format:
	//
	// When using the POST method, the data payload MUST NOT be encoded and
	// is used directly as the HTTP message body.

	// Make sure the 'dns' query parameter is not present.
	if _, ok := req.R.URL.Query()["dns"]; ok {
		http.Error(req.W, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return fmt.Errorf("%s: 'dns' parameter not allowed", http.MethodPost)
	}

	// When using the POST method the DNS query is included as the message
	// body of the HTTP request and the Content-Type request header
	// indicates the media type of the message.
	if req.R.Header.Get("Content-Type") != mime {
		http.Error(req.W, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return fmt.Errorf("%s: Content-Type must be %s", http.MethodPost, mime)
	}

	// Set a limit on body size to protect against DoS.
	// The value 8192 is basically chosen by fair dice roll (common EDNS0 4096 * 2)
	req.R.Body = http.MaxBytesReader(req.W, req.R.Body, 8192)
	body, err := ioutil.ReadAll(req.R.Body)
	if err != nil {
		if err.Error() == "http: request body too large" {
			http.Error(req.W, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
			return err
		}
		http.Error(req.W, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return err
	}

	// An empty body does not make sense.
	if len(body) == 0 {
		http.Error(req.W, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return fmt.Errorf("%s: empty body in request", http.MethodPost)
	}

	rdata, httpStatus, err := req.DB.Query(body)

	if err != nil {
		http.Error(req.W, http.StatusText(httpStatus), httpStatus)
		return err
	}

	req.W.Write(rdata)

	return nil
}
