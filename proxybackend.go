package dohdns

import (
	"github.com/miekg/dns"
	"net"
	"net/http"
	"time"
)

// We use an Exchanger interface to be able to return a custom dns.Msg from
// .Exchange.
type Exchanger interface {
	Exchange(*dns.Msg, string) (*dns.Msg, time.Duration, error)
}

// ProxyBackend passes on queries to a recursive DNS resolver.
type ProxyBackend struct {
	Servers    []string
	Port       string
	ResolvConf string
	Exchanger  Exchanger
}

// NewProxy returns a new ProxyBackend instance.
func NewProxy(servers []string, port string, resolvconf string, exchanger Exchanger) (*ProxyBackend, error) {

	if resolvconf == "" {
		resolvconf = "/etc/resolv.conf"
	}

	// Default to parsing resolve.conf file.
	if servers == nil {
		config, err := dns.ClientConfigFromFile(resolvconf)
		if err != nil {
			return nil, err
		}

		servers = config.Servers
	}

	// Default to port 53.
	if port == "" {
		port = "53"
	}

	// Default to returning a normal dns.Client pointer.
	if exchanger == nil {
		exchanger = new(dns.Client)
	}

	return &ProxyBackend{Servers: servers, Port: port, Exchanger: exchanger}, nil
}

// Query expects to send a request to a recursive DNS resolver.
func (pb *ProxyBackend) Query(qdata []byte) ([]byte, int, error) {
	c := pb.Exchanger
	m := new(dns.Msg)

	err := m.Unpack(qdata)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}

	r, _, err := c.Exchange(m, net.JoinHostPort(pb.Servers[0], pb.Port))
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	rdata, err := r.Pack()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	return rdata, http.StatusOK, nil
}
