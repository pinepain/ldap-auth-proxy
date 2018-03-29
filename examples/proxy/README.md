## Usage:

Let's populate environment with core values:

    export OID='<your JumpCloud organisation id>'
    export LDAP_BIND_USER='<your JumpCloud LDAP bind user name>'
    export LDAP_BIND_PASSWORD='<your JumpCloud LDAP bind user password>'

e.g.:

    export OID='4200000000'
    export LDAP_BIND_USER='jrandom'
    export LDAP_BIND_PASSWORD='password123'


and let's run `docker-compose up`. After that following HTTP endpoints will be available:

 - http://localhost:8080 - publicly available unprotected original page  
 - http://localhost:8888 - LDAP auth proxy
