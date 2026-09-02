# Reference app for vuln-agent's base-image hardening feature (see
# target-apps/README.md). Base is deliberately an older pinned tag so there's a
# real vulnerability surface for the hardening loop to work against.
#
# Note on the compiled-language tradeoff: `runtime-base` ships the Go
# toolchain itself rather than a stripped distroless final stage, specifically
# so `test` can descend from the exact same base as `runtime` (never from an
# unrelated builder stage) — required so a passing `docker build --target
# test` is real evidence about the image that actually gets hardened and
# pushed. A production Dockerfile could instead keep a separate minimal
# runtime stage and have `test` temporarily install the Go toolchain onto
# that same base (`RUN apk add --no-cache go`) — see target-apps/README.md.
FROM golang:1.21-alpine AS runtime-base
WORKDIR /app
COPY go.mod ./
COPY . .
RUN go build -o /app/bin/app .

FROM runtime-base AS test
RUN go vet ./... && go test ./... -v

FROM runtime-base AS runtime
EXPOSE 8080
CMD ["/app/bin/app"]
