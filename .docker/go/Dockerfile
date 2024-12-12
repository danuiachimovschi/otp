FROM golang:1.23.4-alpine

ADD . /golang-otp

ENV GIN_MODE=release
ENV CGO_ENABLED=1
ENV PORT=88
ENV GOWORK off

WORKDIR /golang-otp
RUN export GOPROXY=direct

RUN apk add build-base

# install Makefile
RUN apk add make

# Install curl
RUN apk add --no-cache curl

# install go lint
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.62.2

# Download all the dependencies
RUN go mod download -x

# Install compile daemon for hot reloading
RUN go install -mod=mod github.com/githubnemo/CompileDaemon

# Expose port 80 to the outside world
EXPOSE $PORT

# Command to run the executable
ENTRYPOINT CompileDaemon --build="go build -o main cmd/main.go" --command="./main"
