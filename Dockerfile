FROM golang:1.26.2-bookworm AS builder

WORKDIR /src

ARG TARGETOS=linux
ARG TARGETARCH=amd64

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /out/ddone-server-auth ./cmd/app

FROM debian:bookworm-slim

RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates tzdata \
	&& rm -rf /var/lib/apt/lists/* \
	&& groupadd --system ddone \
	&& useradd --system --gid ddone --home-dir /app --create-home --shell /usr/sbin/nologin ddone

WORKDIR /app

COPY --from=builder /out/ddone-server-auth /usr/local/bin/ddone-server-auth
COPY config ./config

USER ddone:ddone

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/ddone-server-auth"]
