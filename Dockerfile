FROM golang:1.23.3-bookworm as build

RUN apt update

COPY go.mod go.sum /app/
RUN cd /app && go mod download
COPY ./cmd /app/cmd
COPY ./internal /app/internal
RUN cd /app/ && go build -o server cmd/main.go

FROM golang:1.23.3-bookworm as server

COPY --from=build /app/server /app/
ENTRYPOINT ["/app/server"]

