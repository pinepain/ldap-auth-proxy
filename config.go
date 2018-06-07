package main

import (
	log "github.com/sirupsen/logrus"
)

// Config - application config
type Config struct {
	Listen string `default:"0.0.0.0:8888" split_words:"true" desc:"Host and port to listen on"`

	LogFormat string `default:"txt" split_words:"true" desc:"Log format. Allowed values are 'txt' and 'json'"`
	LogLevel  string `default:"info" split_words:"true"`

	URLPathSignIn string `default:"/sign_in" split_words:"true"`
	URLPathAuth   string `default:"/auth" split_words:"true"`

	MessageAuthRequired string `default:"Authorisation required" split_words:"true"`

	Upstream       string `default:"" split_words:"true"`
	PassHostHeader bool   `default:"true" split_words:"true"`

	LdapServer       string            `default:"" split_words:"true" desc:"LDAP server name URL"`
	LdapBase         string            `default:"" split_words:"true"`
	LdapBindDN       string            `default:"" envconfig:"LDAP_BIND_DN"`
	LdapBindPassword string            `default:"" split_words:"true"`
	LdapUserFilter   string            `default:"" split_words:"true"`
	LdapGroupFilter  string            `default:"" split_words:"true"`
	HeadersMap       map[string]string `default:"" split_words:"true" desc:"Comma-separated \"HTTP header\":\"LDAP attribute\" values. \"X-\" prefix will be enforced for all headers."`
	GroupHeader      string            `default:"" split_words:"true" desc:"HTTP header name that holds user group name to filter by, e.g. X-Ldap-Group. * in header value mean no group filter. Multiple groups should be comma-separated and search done using OR filter."`
}

func initLog(c *Config) error {
	if "json" == c.LogFormat {
		log.SetFormatter(&log.JSONFormatter{})
	}

	level, err := log.ParseLevel(c.LogLevel)

	if err == nil {
		log.SetLevel(level)
	}

	return err
}
