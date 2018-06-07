package main

import (
	"encoding/base64"
	"fmt"
	"github.com/jtblin/go-ldap-client"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strings"
)

// LDAPAuthProxy - a struct that represent auth proxy internal configuration
type LDAPAuthProxy struct {
	RobotsPath string
	PingPath   string
	SignInPath string
	AuthPath   string

	SignInMessage string

	LDAPClient     *ldap.LDAPClient
	HeadersMap     map[string]string
	GroupHeader    string
	QueryAttribute string

	serveMux http.Handler
}

// NewLDAPAuthProxy - create new LDAP auth proxy
func NewLDAPAuthProxy(c *Config) (*LDAPAuthProxy, error) {

	l, err := createLDAPClient(c)

	if err != nil {
		return nil, err
	}

	mux, err := NewMux(c)

	if err != nil {
		return nil, err
	}

	p := &LDAPAuthProxy{
		RobotsPath:    "/robots.txt",
		PingPath:      "/ping",
		SignInPath:    c.URLPathSignIn,
		AuthPath:      c.URLPathAuth,
		SignInMessage: c.MessageAuthRequired,

		LDAPClient:  l,
		HeadersMap:  c.HeadersMap,
		GroupHeader: c.GroupHeader,

		serveMux: mux,
	}

	return p, nil
}

// Close - close underlying LDAP connection. The caller is responsible to invoke it.
func (p *LDAPAuthProxy) Close() {
	p.LDAPClient.Close()
}

type loggedResponse struct {
	http.ResponseWriter
	status int
}

func (l *loggedResponse) WriteHeader(status int) {
	l.status = status
	l.ResponseWriter.WriteHeader(status)
}

func (p *LDAPAuthProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	lw := &loggedResponse{ResponseWriter: w}

	switch r.URL.Path {
	case p.RobotsPath:
		p.RobotsTxt(lw)
		break
	case p.PingPath:
		p.PingPage(lw)
		break
	case p.SignInPath:
		p.SignIn(lw, r)
		break
	case p.AuthPath:
		p.AuthenticateOnly(lw, r)
		break
	default:
		p.Proxy(lw, r)
		break
	}

	// TODO: log username and whether status comes from proxy (e.g., add * to denote that it's a status from proxy
	log.Debugf("%s %s %d", r.Method, r.URL, lw.status)
}

// RobotsTxt - serve robots.txt file
func (p *LDAPAuthProxy) RobotsTxt(r http.ResponseWriter) {
	r.WriteHeader(http.StatusOK)
	fmt.Fprintf(r, "User-agent: *\nDisallow: /")
}

// PingPage - serve ping file
func (p *LDAPAuthProxy) PingPage(r http.ResponseWriter) {
	r.WriteHeader(http.StatusOK)
	fmt.Fprintf(r, "OK")
}

// SignIn - serve sign in page
func (p *LDAPAuthProxy) SignIn(w http.ResponseWriter, r *http.Request) {
	status := p.Authenticate(w, r)

	if status != http.StatusAccepted {
		http.Error(w, http.StatusText(status), status)
	} else {
		redirect := r.URL.Query().Get(p.QueryAttribute)
		http.Redirect(w, r, r.Host+redirect, http.StatusFound)
	}
}

// AuthenticateOnly - serve auth-only endpoint
func (p *LDAPAuthProxy) AuthenticateOnly(w http.ResponseWriter, r *http.Request) {
	status := p.Authenticate(w, r)
	if status != http.StatusAccepted {
		http.Error(w, http.StatusText(status), status)
	} else {
		w.WriteHeader(status)
	}
}

// Proxy - proxy incoming request to the upstream
func (p *LDAPAuthProxy) Proxy(w http.ResponseWriter, r *http.Request) {
	status := p.Authenticate(w, r)

	if status != http.StatusAccepted {
		http.Error(w, http.StatusText(status), status)
		return
	}

	p.serveMux.ServeHTTP(w, r)
}

// Authenticate - authenticate user from request
func (p *LDAPAuthProxy) Authenticate(w http.ResponseWriter, r *http.Request) int {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, "Authorization required"))

	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 {
		log.Debug("Malformed auth header value")
		return http.StatusUnauthorized
	}

	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		log.Warningf("Failed to decode HTTP Authorisation header value: %s", err)
		return http.StatusBadRequest
	}

	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		log.Warning("Bad HTTP Authorisation header value")
		return http.StatusBadRequest
	}

	filterGroups := []string{"*"}

	if p.GroupHeader != "" {
		if r.Header.Get(p.GroupHeader) == "" {
			log.Debug("No filterGroups header or empty filterGroups value when it required by configuration")
			return http.StatusBadRequest
		}

		rawGroup := strings.Split(r.Header.Get(p.GroupHeader), ",")

		for _, g := range filterGroups {
			g = strings.TrimSpace(g)

			if "*" == g {
				filterGroups = []string{"*"}
				break
			}

			if len(g) > 1 {
				filterGroups = append(rawGroup, g)
			}
		}

		if len(filterGroups) < 1 {
			return http.StatusBadGateway
		}
	}

	authenticated, attributes, err := p.LDAPClient.Authenticate(pair[0], pair[1])

	if err != nil {
		log.Warning(err)
		// TODO: in fact we may experience LDAP-specific errors here which means we may need to log with error level and return 5XX status code
		return http.StatusUnauthorized
	}

	if !authenticated {
		log.Debug("Not authenticated by LDAP")
		return http.StatusUnauthorized
	}

	// Special case
	if len(filterGroups) > 0 && filterGroups[0] == "*" {
		writeAttributes(p.HeadersMap, attributes, w)
		return http.StatusAccepted
	}

	groupsOfUser, err := p.LDAPClient.GetGroupsOfUser(pair[0])

	if err != nil {
		log.Error(err)
		return http.StatusUnauthorized
	}

	for _, gUser := range groupsOfUser {
		for _, gFilter := range filterGroups {
			if gUser == gFilter {
				writeAttributes(p.HeadersMap, attributes, w)
				return http.StatusAccepted
			}
		}
	}

	log.Debug("Not authorized as per LDAP groups")
	return http.StatusForbidden
}

// writeAttributes - map LDAP attributes back to HTTP headers and write them
func writeAttributes(headers map[string]string, attributes map[string]string, w http.ResponseWriter) {
	log.Debugf("Headers: %+v, Attributes: %+v", headers, attributes)
	for h, a := range headers {
		if !strings.HasPrefix(h, "X-") && !strings.HasPrefix(h, "x-") {
			h = "X-" + h
		}

		w.Header().Set(h, attributes[a])
	}
}
