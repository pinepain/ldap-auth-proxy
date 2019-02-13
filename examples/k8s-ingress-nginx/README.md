# Usage with ingress-nginx in Kubernetes

Note: this is quick and dirty example how to get started, for production use you'd probably want
      to store LDAP credentials in secrets.

This example focuses on JumpCloud LDAP, though any generic LDAP server would work just fine.

## Usage:


Replace following values in `ldap-auth-proxy.yaml`:

 - `<OID>` with your JumpCloud organisation id.
 - `<LDAP_BIND_USER>` with your JumpCloud LDAP bind user name.
 - `<LDAP_BIND_PASSWORD>` with your JumpCloud LDAP bind user password.

e.g.:

 - `<OID>` => `4200000000`
 - `<LDAP_BIND_USER>` => `jrandom`
 - `<LDAP_BIND_PASSWORD>` => `password123`

Also replace `yourdomain.com` in both `httpbin.yaml` and `ldap-auth-proxy.yaml` to your domain.

Now let's deploy all of this to kubernetes:

```
kubectl apply -f ldap-auth-proxy.yaml
kubectl apply -f httpbin.yaml
```
