FROM golang:1.14 AS build

# Cd into the api code directory
WORKDIR /go/src/github.com/pinepain/ldap-auth-proxy

# Copy the local package files to the container's workspace.
ADD . /go/src/github.com/pinepain/ldap-auth-proxy

RUN go get -u github.com/golang/dep/cmd/dep \
    && dep ensure \
    && go vet \
    && CGO_ENABLED=0 GOOS=linux go build \
    && go test -cover

RUN apt-get update && apt-get install --no-install-recommends -y ca-certificates \
    && useradd -u 1000 ldap

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group
COPY --from=build /go/src/github.com/pinepain/ldap-auth-proxy /

USER 1000
CMD ["/ldap-auth-proxy"]
