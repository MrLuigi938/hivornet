# HoneyLite Hive: Sammeln, Speichern, API und Web-UI in einem statischen Binary.
# Basis-Images per Digest festgelegt; Aktualisierung über Dependabot (.github/dependabot.yml).
FROM golang:1.26-alpine@sha256:30b1e546a9c7fa3b747c2bdba3a0c7bdf3a02ebb4c5b8405d2f948d7e8aac4ec AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/hive . \
 && mkdir -p /out/data/geoip /out/data/backups

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/hive /hive
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV HIVE_LISTEN=:8088 HIVE_DB=/data/hive.db HIVE_GEOIP_DIR=/data/geoip
EXPOSE 8088 8089
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/hive", "healthcheck"]
ENTRYPOINT ["/hive"]
