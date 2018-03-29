package main

import (
	"github.com/jtblin/go-ldap-client"
	"github.com/stretchr/testify/assert"
	"testing"
)

func checkPackLDAPAttributes(t *testing.T, headers map[string]string, expected []string) {
	actual := packLDAPAttributes(headers)

	assert.Equal(t, expected, actual, "Arguments to headers packing failed")
}

func TestPackLDAPAttributes(t *testing.T) {
	checkPackLDAPAttributes(t, map[string]string{"header": "attribute"}, []string{"attribute"})
	checkPackLDAPAttributes(t, map[string]string{"header": "attribute", "another": "attribute"}, []string{"attribute", "attribute"})
	checkPackLDAPAttributes(t, map[string]string{"header": ""}, []string{""})
}

func TestConfigureLDAPServer(t *testing.T) {
	client := &ldap.LDAPClient{}

	var err error

	err = configureLDAPServer("|||", client)
	assert.NotNil(t, err)

	err = configureLDAPServer("foo://example.com", client)
	assert.NotNil(t, err)

	err = configureLDAPServer("example.com:aa", client)
	assert.NotNil(t, err)

	err = configureLDAPServer("example.com", client)
	assert.Nil(t, err)
	assert.Equal(t, "example.com", client.Host)
	assert.Equal(t, 389, client.Port)
	assert.Equal(t, false, client.UseSSL)
	assert.Equal(t, "", client.ServerName)
	assert.Equal(t, false, client.InsecureSkipVerify)

	err = configureLDAPServer("example.com:123", client)
	assert.Nil(t, err)
	assert.Equal(t, "example.com", client.Host)
	assert.Equal(t, 123, client.Port)
	assert.Equal(t, false, client.UseSSL)
	assert.Equal(t, "", client.ServerName)
	assert.Equal(t, false, client.InsecureSkipVerify)

	err = configureLDAPServer("ldap://example.com", client)
	assert.Nil(t, err)
	assert.Equal(t, "example.com", client.Host)
	assert.Equal(t, 389, client.Port)
	assert.Equal(t, false, client.UseSSL)
	assert.Equal(t, "", client.ServerName)
	assert.Equal(t, false, client.InsecureSkipVerify)

	err = configureLDAPServer("ldaps://example.com", client)
	assert.Nil(t, err)
	assert.Equal(t, "example.com", client.Host)
	assert.Equal(t, 636, client.Port)
	assert.Equal(t, true, client.UseSSL)
	assert.Equal(t, "example.com", client.ServerName)
	assert.Equal(t, false, client.InsecureSkipVerify)

	err = configureLDAPServer("ldaps://example.com?ServerName=alt-example.com&InsecureSkipVerify=garbage", client)
	assert.NotNil(t, err)

	err = configureLDAPServer("ldaps://example.com?ServerName=alt-example.com&InsecureSkipVerify=true", client)
	assert.Nil(t, err)
	assert.Equal(t, "example.com", client.Host)
	assert.Equal(t, 636, client.Port)
	assert.Equal(t, true, client.UseSSL)
	assert.Equal(t, "alt-example.com", client.ServerName)
	assert.Equal(t, true, client.InsecureSkipVerify)

	err = configureLDAPServer("ldaps://example.com?ServerName=alt-example.com&InsecureSkipVerify=false", client)
	assert.Nil(t, err)
	assert.Equal(t, "example.com", client.Host)
	assert.Equal(t, 636, client.Port)
	assert.Equal(t, true, client.UseSSL)
	assert.Equal(t, "alt-example.com", client.ServerName)
	assert.Equal(t, false, client.InsecureSkipVerify)
}
