FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder
ARG TARGETARCH
ARG APP
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -o /out/app ./cmd/${APP}

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/app /app
ENTRYPOINT ["/app"]
