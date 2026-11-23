# Runtime image: the release's static binary on distroless, non-root, no
# shell. It packages the binaries release.yml has already built, checked and
# signed; nothing is compiled here. To build one locally:
#
#   make build && mkdir -p dist && cp bin/dropr dist/dropr-dev-linux-amd64
#   docker build --build-arg VERSION=dev -t dropr:dev .
#
# Running it: docs/deploy.md.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
ARG TARGETARCH
ARG VERSION
LABEL org.opencontainers.image.title="dropr" \
      org.opencontainers.image.description="Self-hosted, end-to-end encrypted file drop" \
      org.opencontainers.image.source="https://github.com/Scttpr/Dropr" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
COPY --chmod=0755 dist/dropr-${VERSION}-linux-${TARGETARCH} /usr/local/bin/dropr
# The binary probes its own /healthz: the image has no shell or curl.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD ["/usr/local/bin/dropr", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/dropr"]
CMD ["serve"]
