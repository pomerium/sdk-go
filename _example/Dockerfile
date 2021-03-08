FROM golang:latest as build
WORKDIR /go/src/verify
ADD . /go/src/verify
RUN go env -w GO111MODULE=auto
RUN go get -d -v ./...
RUN go build -o /go/bin/verify main.go

FROM gcr.io/distroless/base
COPY --from=build /go/bin/verify /
ENTRYPOINT [ "/verify" ]