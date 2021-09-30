FROM golang:1.17.1 as builder

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a --ldflags '-w -extldflags "-static"' -tags netgo -installsuffix netgo -o gcp-logs-slack-notifier .


FROM alpine:3.14 as certs

RUN apk add --no-cache ca-certificates


FROM scratch

COPY --from=builder /workspace/gcp-logs-slack-notifier /
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

USER 65534:65534

ENTRYPOINT ["/gcp-logs-slack-notifier"]
