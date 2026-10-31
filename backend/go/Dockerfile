# One builder, one tiny final stage per binary (12 §Dockerfiles). Build a target with --target <name>.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG CMD
RUN test -n "$CMD" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/$CMD

FROM gcr.io/distroless/static:nonroot AS runtime
COPY --from=build /out/app /app
COPY --from=build /src/rules /rules
COPY --from=build /src/maze /maze
USER nonroot
ENTRYPOINT ["/app"]
