# Coding Exercise: Simple OAuth2 Server

## Brief Description of Folders and Files Structure

Using the latest Go version, because it contains performance improvements, optimizations and security patches.

Folders:
`pkg` - contains Go packages that can be used in other applications, if required
`app` - folder contains application business
`cmd` - contains the main Go files

Inside each subfolder of the `app`, the following files can be found:

`handlers.go` - contains the http server handlers, usually in a form of closure functions.
The composition of handlers, services and repositories takes place in the `main.go` file.

`requests.go` - contains all the structs that represent the payloads the servers accepts. The file can contain
implementations of `Unmarshal` json, potential payload validation.

`responses.go` - contains all the structs that represent the server responses. Same as `requests.go` file, can contain
implementation of `Marshal`.

`service.go` - the business logic for features that the application package has.

`repository.go` - the storage layer, if it is the case.

Note that handlers takes an Service interface, so we can write tests. Same goes for service, which accepts a Repository
interface.

All interfaces are defined where they are used : even if all the files are in the same folder, it is a Go language best
practice recommendation.

## External Packages Used

[`logrus`](https://github.com/sirupsen/logrus) - logging

[`jwt`](https://github.com/golang-jwt/jwt/v5) - JSON Web Tokens implementation 

[`mux`](https://github.com/gorilla/mux) - router

[`handlers`](https://github.com/gorilla/handlers) - CORS

[`http-swagger`](https://github.com/swaggo/http-swagger) - Swagger documentation

## Configuration

The following environment variables allows customization of the server:

* `JWT_TOKEN_SECRET` - it is the key used to generate tokens. If not provided, we use random generated key.

* `JWT_TOKEN_DURATION` - expiration of the tokens in hours. Default to 8 hours.

* `JWT_SIGNING_METHOD` - default method used to sign tokens.

* `ALLOWED_CORS_URL` - URLs of a possible frontend (SPA) application that would be allowed to use this server.

* `ALLOWED_CORS_HEADERS` - All possible request headers that the SPA can use in requesting this server.

* `ALLOW_PPROF` - If set to "true", opens routes to pprof the server.

* `APP_HTTP_PORT` - Defaults to 8080, but we allow customization.
