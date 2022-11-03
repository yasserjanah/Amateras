FROM golang:1.16-alpine AS build-env
RUN apk add --no-cache --upgrade git openssh-client ca-certificates
RUN apk add build-base gcc wget git libpcap-dev

WORKDIR /go/src/app

COPY . /go/src/app


RUN go mod download

RUN go build -o amateras main.go dhcp.go

ENTRYPOINT ["./amateras"]
