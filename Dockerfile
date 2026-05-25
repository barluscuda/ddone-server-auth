FROM golang:1.26.2-alpine AS builder

WORKDIR /src

ARG TARGETOS=linux
ARG TARGETARCH=amd64

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /out/ddone-server-auth ./cmd/app

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata \
	&& addgroup -S ddone \
	&& adduser -S -D -H -s /sbin/nologin -G ddone ddone

WORKDIR /app

COPY --from=builder /out/ddone-server-auth /usr/local/bin/ddone-server-auth
COPY config/config.yaml ./config/config.yaml

USER ddone:ddone

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/ddone-server-auth"]
