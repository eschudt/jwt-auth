FROM golang:1.10-alpine as builder
RUN apk update && apk add --no-cache git make curl

ARG PROJECT
ARG APP_VERSION
ARG GITHASH
ARG BUILDSTAMP

WORKDIR /go/src/github.com/eschudt/jwt-auth
COPY . /go/src/github.com/eschudt/jwt-auth

RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh && make build-local

FROM alpine:3.7
RUN apk update && apk add --no-cache ca-certificates
COPY --from=builder /app /app

EXPOSE 8080

ENTRYPOINT ["/app"]
