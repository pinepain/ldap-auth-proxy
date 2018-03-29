package main

import (
	"fmt"
	"github.com/jtblin/go-ldap-client"
	"net/url"
	"strconv"
	"strings"
)

func createLDAPClient(c *Config) (*ldap.LDAPClient, error) {
	client := &ldap.LDAPClient{}

	err := configureLDAPServer(c.LdapServer, client)

	if err != nil {
		return nil, err
	}

	client.Attributes = packLDAPAttributes(c.HeadersMap)

	client.Base = c.LdapBase
	client.BindDN = c.LdapBindDN
	client.BindPassword = c.LdapBindPassword
	client.UserFilter = c.LdapUserFilter
	client.GroupFilter = c.LdapGroupFilter

	return client, nil
}

func configureLDAPServer(rawURL string, client *ldap.LDAPClient) error {
	if strings.Index(rawURL, "://") < 0 {
		rawURL = "ldap://" + rawURL
	}

	u, err := url.Parse(rawURL)

	if err != nil {
		return err
	}

	q, err := url.ParseQuery(u.RawQuery)

	if err != nil {
		return err
	}

	host := u.Hostname()
	port := 389 // tcp
	useSSL := false

	if u.Scheme != "" && u.Scheme != "ldap" && u.Scheme != "ldaps" {
		return fmt.Errorf("invalid LDAP server URL scheme: %s", u.Scheme)
	}

	if u.Scheme == "ldaps" {
		useSSL = true
		port = 636 // ssl
	}

	if u.Port() != "" {
		raw, err := strconv.Atoi(u.Port())
		if err != nil {
			return fmt.Errorf("invalid LDAP server URL port: %s", u.Port())
		}

		port = raw
	}

	client.Host = host
	client.Port = port
	client.UseSSL = useSSL

	if useSSL {
		client.ServerName = host
	}

	if q.Get("ServerName") != "" {
		client.ServerName = q.Get("ServerName")
	}

	if q.Get("InsecureSkipVerify") != "" {
		v, err := strconv.ParseBool(q.Get("InsecureSkipVerify"))

		if err != nil {
			return err
		}

		client.InsecureSkipVerify = v
	}

	return nil
}

func packLDAPAttributes(headers map[string]string) []string {

	a := make([]string, 0, len(headers))

	for _, val := range headers {
		a = append(a, val)
	}

	return a
}
