FROM --platform=$BUILDPLATFORM tonistiigi/xx AS xx

FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS build
RUN apk add clang lld git
COPY --from=xx / /


WORKDIR /go/src/app
COPY go.mod go.mod
COPY go.sum go.sum

RUN xx-go mod download

COPY . .

RUN go test ./...

ARG TARGETPLATFORM
RUN xx-apk add musl-dev gcc

ENV CGO_ENABLED=1
RUN xx-go build -ldflags "-linkmode 'external' -extldflags '-static'" -o ./auththingie2 . && \
    xx-verify --static ./auththingie2

FROM gcr.io/distroless/static-debian12:latest

ENV ENVIRONMENT=prod
ENV AT2_MODE=docker
EXPOSE 9000

HEALTHCHECK --interval=5s --timeout=5s CMD ["/auththingie", "healthcheck", "-c", "-t", "4"]

COPY --from=build /go/src/app/auththingie2 ./auththingie

CMD ["./auththingie"]
