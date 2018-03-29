# LDAP Auth proxy

[![Build Status](https://api.travis-ci.org/pinepain/ldap-auth-proxy.svg?branch=master)](https://travis-ci.org/pinepain/ldap-auth-proxy)
[![codecov](https://codecov.io/gh/pinepain/ldap-auth-proxy/branch/master/graph/badge.svg)](https://codecov.io/gh/pinepain/ldap-auth-proxy)
[![Go Report Card](https://goreportcard.com/badge/github.com/pinepain/ldap-auth-proxy)](https://goreportcard.com/report/github.com/pinepain/ldap-auth-proxy)

A simple drop-in HTTP proxy for transparent LDAP authorisation which could be also used as HTTP auth backend.


## Architecture





## Example settings for JumpCloud users:

    export LDAP_SERVER='ldaps://ldap.jumpcloud.com'
    export LDAP_BASE='o=<iod>,dc=jumpcloud,dc=com'
    export LDAP_BIND_DN='uid=<bind user name>,ou=Users,o=<oid>,dc=jumpcloud,dc=com'
    export LDAP_BIND_PASSWORD='<bind user password>'
    export LDAP_USER_FILTER='(uid=%s)'
    export LDAP_GROUP_FILTER='(&(objectClass=groupOfNames)(member=uid=%s,ou=Users,o=<oid>,dc=jumpcloud,dc=com))'
    export HEADERS_MAP='X-LDAP-Mail:mail,X-LDAP-UID:uid,X-LDAP-CN:cn,X-LDAP-DN:dn'

where `<oid>` is your organisation id.
