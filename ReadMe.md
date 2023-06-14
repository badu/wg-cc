# Coding Exercise: Simple OAuth2 Server

## Brief Description of Folders and Files Structure

Using the latest Go version, because it contains performance improvements, optimizations, and security patches.

Folders:

`pkg` - contains Go packages that can be used in other applications, if required

`app` - folder contains application business

`cmd` - contains the main Go files

Inside each subfolder of the `app`, the following files can be found:

`handlers.go` - contains the http server handlers, usually in a form of closure functions.
The composition of handlers, services and repositories takes place in the `main.go` file.

`requests.go` - contains all the structs that represent the payloads the server accepts. The file can contain
implementations of `Unmarshal` json, potential payload validation.

`responses.go` - contains all the structs that represent the server responses. Same as `requests.go` file, can contain
implementation of `Marshal`.

`service.go` - the business logic for features that the application package has. Due to separation of concerns, it deals
with all cryptographic operations, thus having transport doing transport things and repository doing storage related
work.

`repository.go` - the storage layer, if it is the case. Instead of using a domain object, we expand all properties

Note that handlers take an Service interface, so we can write tests. The same goes for service, which accepts a
Repository
interface.

All interfaces are defined where they are used: even if all the files are in the same folder, it is a Go language best
practice recommendation.

All compositions take place in the main application. The reason for this is due to the fact that we can have many
flavors of applications (AWS lambda, microservice, monolith) that should compose the components and adapt to their
respective conditions. For this reason, the `Dockerfile` sits next to the `main.go` file and each flavor of the
application will have one.

I've used SQLite 3, but for scaling purposes we can use [`rqlite`](https://github.com/rqlite/rqlite) in the future.

## External Packages Used

[`logrus`](https://github.com/sirupsen/logrus) - logging

[`jwt`](https://github.com/golang-jwt/jwt/v5) - JSON Web Tokens implementation, latest version (v5)

[`mux`](https://github.com/gorilla/mux) - router from Gorilla

[`handlers`](https://github.com/gorilla/handlers) - CORS capabilities from Gorilla

[`http-swagger`](https://github.com/swaggo/http-swagger) - Swagger documentation, facilitate demo

[`crypto`](https://golang.org/x/crypto) - for bcrypt, avoid storing client_secret in plain text in the database

## Internal Packages

In order to graceful shutdown, there are two packages `runner` and `signal`. For allowing creation of signing keys and
adding clients, there is a very simple `totp` package.

## Configuration

The following environment variables allow customization of the server:

* `JWT_TOKEN_DURATION` - expiration of the tokens in hours. Default to 8 hours.

* `JWT_SIGNING_METHOD` - default method used to sign tokens. Valid methods are RS384, RS512 and RS256. RS256 is default.

* `ALLOWED_CORS_URL` - URLs of a possible frontend (SPA) application that would be allowed to use this server.

* `ALLOWED_CORS_HEADERS` - All possible request headers that the SPA can use in requesting this server.

* `ALLOW_PPROF` - If set to "true", opens routes to pprof the server.

* `APP_HTTP_PORT` - Defaults to 8080, but we allow customization.

## Kubernetes & Docker

build the container image, in the root of this project:

`docker build . -t oauth-server:1.0.0 -f ./cmd/oauth2-server/Dockerfile`

Running the built image:

`docker run -p 8080:8080 oauth-server:1.0.0`

You can now run integration test if you like.

Apply the deployment and service manifests using the following commands:

`kubectl apply -f deployment.yaml`

`kubectl apply -f service.yaml`

Use the following command to retrieve the external IP:

`kubectl get services`

Look for the EXTERNAL-IP column of the oauth2-server

## Usage & Demo

In the database, there are three tables:

- one which keeps clients by their id, secrets and key name which will be used to sign the JWT token
- of course, a table which holds the RSA keys which are used in point 1
- a table for holding the `audit`, the issues JWT tokens, which is being used when introspecting a token

1. Start the server locally, as any normal Go language application. When the server starts, look
   for `administration TOTP key` message in the console and copy
   the value of the TOTP secret
2. We need to create at least one private key and onboard one user. Point your browser
   towards [Swagger page](http://localhost:8080/docs/index.html)
3. Go to [this endpoint](http://localhost:8080/docs/index.html#/token/declare-clients-and-keys) and complete the
   following: `operation_type` = `create_key` and `totp` = the code you've obtained in step 1. Give the key a valid
   name, by completing `key_name` form field.
4. On the same endpoint, replace `operation_type` = `create_client` and provide `key_name` (signing key for that
   client), `client_id` and `client_secret`. Client secret will be stored encrypted in the database.
5. Repeat for generating sigining keys and adding clients as needed. Note that client_id must be unique (no checks are
   done at the moment)
6. You can use [this endpoint](http://localhost:8080/docs/index.html#/token/create-token) to test jwt signing by
   providing the client id and secret declared on each client. The signing will be done using the key associated on
   onboarding.
7. Test other endpoints as well, by using the same Swagger interface.

## Final note

For any additional questions regarding this project, please feel free to contact me directly via email. 
