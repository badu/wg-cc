
# Use the official Golang 1.20 image as the base image
FROM golang:1.20-alpine as builder

MAINTAINER Bogdan DINU <badu@badu.ro>

WORKDIR /project

# Reduce the number of build layers
RUN apk update \
    && apk add git make  \
    && apk add --no-cache --virtual .build-deps \
           ca-certificates \
           gcc \
           g++;

COPY . .

RUN go mod download -x ;
# Build the server executable
RUN go env && go build -v -o ./build/service github.com/badu/wg-cc/cmd/oauth2-server ;

FROM alpine:3.15

RUN apk update \
    && apk add --no-cache ca-certificates tzdata ;

WORKDIR /app

# Copy the server code into the container
COPY --from=builder /project/build /app

# Define the command to run when the container starts
CMD /app/service ;
