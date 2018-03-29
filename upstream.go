package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

// UpstreamProxy - a struct that represent proxy to upstream
type UpstreamProxy struct {
	URL            *url.URL
	PassHostHeader bool
	Handler        http.Handler
}

// NewMux - creates new HTTP multiplexer to handle requests to upstream
func NewMux(c *Config) (http.Handler, error) {
	serveMux := http.NewServeMux()

	if c.Upstream != "" {
		up, err := NewUpstream(c)

		if err != nil {
			return nil, err
		}

		serveMux.Handle("/", up)
	} else {
		serveMux.HandleFunc("/", BadGatewayHandler)
	}

	return serveMux, nil
}

func (u *UpstreamProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.Handler.ServeHTTP(w, r)
}

func (u *UpstreamProxy) setProxyUpstreamHostHeader(proxy *httputil.ReverseProxy, target *url.URL) {
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		// use RequestURI so that we aren't unescaping encoded slashes in the request path
		if u.PassHostHeader {
			req.Host = target.Host
		}
		req.URL.Opaque = req.RequestURI
		req.URL.RawQuery = ""
	}
}

// BadGatewayHandler - default handler which is used when no upstream set
func BadGatewayHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
}

// NewReverseProxy - create new reverse proxy
func NewReverseProxy(target *url.URL) (proxy *httputil.ReverseProxy) {
	return httputil.NewSingleHostReverseProxy(target)
}

// NewUpstream - create new upstream proxy
func NewUpstream(c *Config) (*UpstreamProxy, error) {

	upstreamURL, err := url.Parse(c.Upstream)

	if err != nil {
		return nil, err
	}

	upstreamURL.Path = ""

	u := &UpstreamProxy{
		URL:            upstreamURL,
		PassHostHeader: c.PassHostHeader,
		Handler:        NewReverseProxy(upstreamURL),
	}

	return u, nil
}
