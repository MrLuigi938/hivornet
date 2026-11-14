# HoneyLite Honeypot: ein Prozess für alle Protokolle, läuft ohne Root.
# Basis-Images per Digest festgelegt; Aktualisierung über Dependabot (.github/dependabot.yml).
FROM golang:1.27-alpine@sha256:eb61c3873c97416fff0116553fff65d67a3549f72e11d9758849a689cdd8b523 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/honeypot .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/honeypot /honeypot
USER 65532:65532
# Ports unter 1024 lauschen im Container auf Port+10000 (80 -> 10080),
# damit keine Root-Rechte oder Kernel-Sonderfunktionen nötig sind.
ENV HONEYPOT_LOW_PORT_OFFSET=10000 HONEYPOT_CONFIG=/etc/honeylite/honeypot.yml
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/honeypot", "healthcheck"]
ENTRYPOINT ["/honeypot"]
