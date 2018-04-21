package dohdns_test

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/eest/dohdns"
	"github.com/miekg/dns"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"syscall"
	"testing"
	"time"
)

var requestTests = []struct {
	desc            string
	handler         func(dohdns.Database, *log.Logger) http.HandlerFunc
	url             string
	method          string
	status          int
	reqContentType  string
	reqBody         []byte
	reqBodyError    bool
	respContentType string
	respBody        []byte
	brokenExchange  bool
}{
	{
		desc:            "GET with no 'dns' parameter",
		handler:         dohdns.HandleRequest,
		method:          "GET",
		url:             "https://example.com",
		status:          http.StatusBadRequest,
		respContentType: "text/plain; charset=utf-8",
		respBody:        []byte("Bad Request\n"),
	},
	{
		desc:            "GET with empty 'dns' parameter",
		handler:         dohdns.HandleRequest,
		method:          "GET",
		url:             "https://example.com?dns=",
		status:          http.StatusBadRequest,
		respContentType: "text/plain; charset=utf-8",
		respBody:        []byte("Bad Request\n"),
	},
	{
		desc:            "GET with multiple 'dns' parameters",
		handler:         dohdns.HandleRequest,
		method:          "GET",
		url:             "https://example.com?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB&dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
		status:          http.StatusUnprocessableEntity,
		respContentType: "text/plain; charset=utf-8",
		respBody:        []byte("Unprocessable Entity\n"),
	},
	{
		desc:            "GET with unparseable base64url",
		handler:         dohdns.HandleRequest,
		method:          "GET",
		url:             "https://example.com?dns=!",
		status:          http.StatusBadRequest,
		respContentType: "text/plain; charset=utf-8",
		respBody:        []byte("Bad Request\n"),
	},
	{
		desc:            "GET with parseable base64url that is not a valid DNS query",
		handler:         dohdns.HandleRequest,
		method:          "GET",
		url:             "https://example.com?dns=invalid",
		status:          http.StatusBadRequest,
		respContentType: "text/plain; charset=utf-8",
		respBody:        []byte("Bad Request\n"),
	},
	{
		desc:            "GET with valid www.example.com (A) query",
		handler:         dohdns.HandleRequest,
		method:          "GET",
		url:             "https://example.com?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
		status:          http.StatusOK,
		respContentType: "application/dns-udpwireformat",
	},
	{
		desc:            "GET with valid www.example.com (A) where the Exchange function returns a broken DNS packet",
		handler:         dohdns.HandleRequest,
		method:          "GET",
		url:             "https://example.com?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
		status:          http.StatusInternalServerError,
		respContentType: "text/plain; charset=utf-8",
		respBody:        []byte("Internal Server Error\n"),
		brokenExchange:  true,
	},
	{
		desc:            "GET with valid www.example.com (A) query and custom backend port",
		handler:         dohdns.HandleRequest,
		method:          "GET",
		url:             "https://example.com?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
		status:          http.StatusOK,
		respContentType: "application/dns-udpwireformat",
	},
	{
		desc:            "GET with valid noresponse.example.com (A) query that should time out",
		handler:         dohdns.HandleRequest,
		method:          "GET",
		url:             "https://example.com?dns=AAABAAABAAAAAAAACm5vcmVzcG9uc2UHZXhhbXBsZQNjb20AAAEAAQ",
		status:          http.StatusInternalServerError,
		respContentType: "text/plain; charset=utf-8",
		respBody:        []byte("Internal Server Error\n"),
	},
	{
		desc:            "POST with wrong Content-Type",
		handler:         dohdns.HandleRequest,
		method:          "POST",
		url:             "https://example.com",
		status:          http.StatusUnsupportedMediaType,
		respContentType: "text/plain; charset=utf-8",
		respBody:        []byte("Unsupported Media Type\n"),
	},
	{
		desc:            "POST with correct Content-Type but no body",
		handler:         dohdns.HandleRequest,
		method:          "POST",
		url:             "https://example.com",
		status:          http.StatusBadRequest,
		respContentType: "text/plain; charset=utf-8",
		respBody:        []byte("Bad Request\n"),
		reqContentType:  "application/dns-udpwireformat",
	},
	{
		desc:            "POST with valid www.example.com (A) query",
		handler:         dohdns.HandleRequest,
		method:          "POST",
		url:             "https://example.com",
		status:          http.StatusOK,
		reqBody:         []byte{0x0, 0x0, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x77, 0x77, 0x77, 0x7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1},
		reqContentType:  "application/dns-udpwireformat",
		respContentType: "application/dns-udpwireformat",
	},
	{
		desc:            "POST with valid noresponse.example.com (A) query that should time out",
		handler:         dohdns.HandleRequest,
		method:          "POST",
		url:             "https://example.com",
		status:          http.StatusInternalServerError,
		reqBody:         []byte{0x0, 0x0, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x6e, 0x6f, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1},
		reqContentType:  "application/dns-udpwireformat",
		respContentType: "text/plain; charset=utf-8",
		respBody:        []byte("Internal Server Error\n"),
	},
	{
		desc:            "POST with valid query but empty and misplaced 'dns' parameter",
		handler:         dohdns.HandleRequest,
		method:          "POST",
		url:             "https://example.com?dns=",
		status:          http.StatusBadRequest,
		reqBody:         []byte{0x0, 0x0, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x77, 0x77, 0x77, 0x7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1},
		reqContentType:  "application/dns-udpwireformat",
		respContentType: "text/plain; charset=utf-8",
		respBody:        []byte("Bad Request\n"),
	},
	{
		desc:            "POST with valid query and valid but misplaced 'dns' parameter",
		handler:         dohdns.HandleRequest,
		method:          "POST",
		url:             "https://example.com?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB",
		status:          http.StatusBadRequest,
		reqBody:         []byte{0x0, 0x0, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x77, 0x77, 0x77, 0x7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1},
		reqContentType:  "application/dns-udpwireformat",
		respContentType: "text/plain; charset=utf-8",
		respBody:        []byte("Bad Request\n"),
	},
	{
		desc:            "POST with too large request Body",
		handler:         dohdns.HandleRequest,
		method:          "POST",
		url:             "https://example.com",
		status:          http.StatusRequestEntityTooLarge,
		reqBody:         make([]byte, 8193),
		reqContentType:  "application/dns-udpwireformat",
		respBody:        []byte("Request Entity Too Large\n"),
		respContentType: "text/plain; charset=utf-8",
	},
	{
		desc:            "POST with unreadable Body",
		handler:         dohdns.HandleRequest,
		method:          "POST",
		url:             "https://example.com",
		status:          http.StatusInternalServerError,
		reqBodyError:    true,
		reqContentType:  "application/dns-udpwireformat",
		respBody:        []byte("Internal Server Error\n"),
		respContentType: "text/plain; charset=utf-8",
	},
	{
		desc:            "Unsupported PUT method",
		handler:         dohdns.HandleRequest,
		method:          "PUT",
		url:             "https://example.com",
		status:          http.StatusMethodNotAllowed,
		respBody:        []byte("Method Not Allowed\n"),
		respContentType: "text/plain; charset=utf-8",
	},
}

// errReader is used to test failing reads of the request body.
type errReader struct{}

// Make errReader an io.Reader.
func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("test error")
}

// Used to create mock replies to ProxyBackend.
type dnsRequestHandler struct{}

func (h *dnsRequestHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {

	switch r.Question[0].Qtype {
	case dns.TypeA:
		qname := r.Question[0].Name

		switch qname {
		case "www.example.com.":
			msg := dns.Msg{}
			msg.SetReply(r)
			msg.Authoritative = true
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("127.0.0.1"),
			})
			w.WriteMsg(&msg)
		default:
			// Do nothing, the client will time out.
		}
	}
}

// We use this type to overwrite the Exchange method below.
type brokenExchangeClient struct {
	dns.Client
}

func (c *brokenExchangeClient) Exchange(m *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
	return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: -1}}, 0, nil
}

func TestRequests(t *testing.T) {

	// Start up an internal DNS server for test queries.
	internalDNSPort := "53535"
	internalDNSAddr := "127.0.0.1"
	internalDNSProto := "udp"

	dnsServerReady := make(chan struct{})
	dnsHandler := &dnsRequestHandler{}
	dnsServer := &dns.Server{
		Addr:    fmt.Sprintf("%s:%s", internalDNSAddr, internalDNSPort),
		Net:     internalDNSProto,
		Handler: dnsHandler,
		NotifyStartedFunc: func(dnsServerReady chan struct{}) func() {
			return func() {
				close(dnsServerReady)
			}
		}(dnsServerReady),
	}
	go dnsServer.ListenAndServe()
	// Wait until DNS server is ready to serve requests before continuing.
	<-dnsServerReady

	// Create a silent logger to got more complete test coverage.
	logger := log.New(ioutil.Discard, "", 0)

	for _, test := range requestTests {

		// Direct DNS queries to our local test DNS server.
		var database *dohdns.ProxyBackend
		var err error

		if test.brokenExchange {
			database, err = dohdns.NewProxy(
				[]string{internalDNSAddr},
				internalDNSPort,
				"",
				&brokenExchangeClient{},
			)
			if err != nil {
				t.Errorf(
					"%s: unable to instantiate brokenExchangeClient NewProxy: %s",
					test.desc,
					err,
				)
			}
		} else {
			database, err = dohdns.NewProxy([]string{internalDNSAddr}, internalDNSPort, "", nil)
			if err != nil {
				t.Errorf(
					"%s: unable to instantiate default NewProxy: %s",
					test.desc,
					err,
				)
			}
		}

		var req *http.Request
		switch test.method {
		case "POST":
			if test.reqBodyError {
				req = httptest.NewRequest(test.method, test.url, errReader{})
			} else {
				r := bytes.NewReader(test.reqBody)
				req = httptest.NewRequest(test.method, test.url, r)
			}
			if test.reqContentType != "" {
				req.Header.Set("Content-Type", test.reqContentType)
			}
		default:
			req = httptest.NewRequest(test.method, test.url, nil)
		}
		w := httptest.NewRecorder()

		handler := dohdns.HandleRequest(database, logger)
		handler.ServeHTTP(w, req)

		resp := w.Result()
		respBody, _ := ioutil.ReadAll(resp.Body)

		// Verify status code
		if resp.StatusCode != test.status {
			t.Errorf(
				"%s: unexpected status code (got %d, want %d)",
				test.desc,
				resp.StatusCode,
				test.status,
			)
		}

		// Verify Content-Type header.
		if resp.Header.Get("Content-Type") != test.respContentType {
			t.Errorf(
				"%s: unexpected Content-Type (got \"%s\", want \"%s\")",
				test.desc,
				resp.Header.Get("Content-Type"),
				test.respContentType,
			)
		}

		// Verify respBody content.
		if resp.StatusCode == http.StatusOK {
			// For successful code try to parse respBody as DNS wire format data.
			m := new(dns.Msg)
			if err := m.Unpack(respBody); err != nil {
				t.Errorf(
					"%s: unable to parse DNS data in successful request",
					test.desc,
				)
			}
		} else {
			// Verify we receive the expected error respBody contents.
			if !bytes.Equal(respBody, test.respBody) {
				t.Errorf(
					"%s: unexpected respBody (got \"%#v\", want \"%#v\")",
					test.desc,
					respBody,
					test.respBody,
				)
			}
		}
	}
}

var newProxyTests = []struct {
	desc       string
	servers    []string
	port       string
	resolvconf string
	err        error
	database   *dohdns.ProxyBackend
	exchanger  *dohdns.Exchanger
}{
	{
		desc:       "Default settings",
		servers:    nil,
		port:       "",
		resolvconf: "",
		database:   &dohdns.ProxyBackend{},
		err:        nil,
	},
	{
		desc:       "Nonexistant resolv.conf",
		servers:    nil,
		port:       "",
		resolvconf: "/nonexistent-resolv.conf",
		database:   nil,
		err:        &os.PathError{Op: "open", Path: "/nonexistent-resolv.conf", Err: syscall.Errno(syscall.ENOENT)},
	},
}

func TestNewProxy(t *testing.T) {
	// For the default case when no servers are supplied we
	// need to parse /etc/resolv.conf to know what should
	// exist in the resulting struct.
	clientConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		t.Fatalf(
			"TestNewProxy: unable to parse /etc/resolv.conf: %s",
			err,
		)
	}

	for _, test := range newProxyTests {
		database, err := dohdns.NewProxy(test.servers, test.port, test.resolvconf, nil)

		// If test.servers is not defined and there was no error
		// calling NewProxy we need to update the expected database
		// to contain the system servers.
		if test.servers == nil && err == nil {
			test.database.Servers = clientConfig.Servers
		}

		// If port is not set and there was no error calling NewProxy
		// we expect the default to be "53"
		if test.port == "" && err == nil {
			test.database.Port = "53"
		}

		// If exchanger is not set and there was no error calling NewProxy
		// we expect the default to be a normal dns.Client pointer.
		if test.exchanger == nil && err == nil {
			test.database.Exchanger = new(dns.Client)
		}

		if !reflect.DeepEqual(err, test.err) {
			t.Errorf(
				"%s: unexpected err (got \"%#v\", want \"%#v\")",
				test.desc,
				err,
				test.err,
			)
		}

		if !reflect.DeepEqual(database, test.database) {
			t.Errorf(
				"%s: unexpected database (got \"%v\", want \"%v\")",
				test.desc,
				database,
				test.database,
			)
		}
	}
}
