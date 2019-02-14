FROM golang:1.11 AS build

# Cd into the api code directory
WORKDIR /go/src/github.com/pinepain/ldap-auth-proxy

# Copy the local package files to the container's workspace.
ADD . /go/src/github.com/pinepain/ldap-auth-proxy

RUN go get -u github.com/golang/dep/cmd/dep \
    && dep ensure \
    && go vet \
    && CGO_ENABLED=0 GOOS=linux go build \
    && go test -cover


FROM ubuntu:bionic AS ubuntu
RUN apt-get update && apt-get install --no-install-recommends -y ca-certificates


FROM scratch
COPY --from=ubuntu /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /go/src/github.com/pinepain/ldap-auth-proxy /

ENTRYPOINT ["/ldap-auth-proxy"]
