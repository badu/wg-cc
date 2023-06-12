package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/badu/wg-cc/app/login"
	"github.com/badu/wg-cc/pkg/runner"
	"github.com/badu/wg-cc/pkg/signal"
)

const (
	JWT_TOKEN_DURATION    = "JWT_TOKEN_DURATION"
	JWT_TOKEN_SECRET      = "JWT_TOKEN_SECRET"
	JWT_SIGNING_METHOD    = "JWT_SIGNING_METHOD"
	ALLOWED_CORS_URL      = "ALLOWED_CORS_URL"
	ALLOWED_CORS_HEADERS  = "ALLOWED_CORS_HEADERS"
	ALLOW_PPROF           = "ALLOW_PPROF"
	SERVER_PORT           = "APP_HTTP_PORT"
	defaultJWTDurationStr = "8" // in hours

	defaultJWTSignMethod = "HS256" // default signing method is jwt.SigningMethodHS256

	HeaderContentTypeValue = "application/json; charset=UTF-8"
	HeaderContentType      = "Content-Type"
)

var allowedCorsRequestHeaders = "Accept,Cookie,Authorization,Content-Type,Content-Range,X-Requested-With,X-Search,X-UUID"

var allowedCorsMethods = []string{
	http.MethodGet,
	http.MethodPost,
	http.MethodPatch,
	http.MethodPut,
	http.MethodDelete,
	http.MethodOptions,
}

type RouteNotFound struct {
	Message string
}

func Logger(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			inner.ServeHTTP(w, r)
			log.Printf(
				"%s %s %s %s",
				r.Method,
				r.RequestURI,
				name,
				time.Since(start),
			)
		})
}

func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				stacktrace := string(debug.Stack())
				log.Printf("PANIC RECOVERED:\n%v", err)
				log.Println(stacktrace)
				return
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// @title OAuth 2 Server
// @version 1.0
// @description This is API server.
// @termsOfService http://swagger.io/terms/

// @host localhost:8080
// @query.collection.format multi

// @securityDefinitions.basic BasicAuth

func main() {
	switch os.Getenv("LOG_LEVEL") {
	case "EMERG":
		logrus.SetLevel(logrus.ErrorLevel)
	case "ALERT":
		logrus.SetLevel(logrus.ErrorLevel)
	case "CRIT":
		logrus.SetLevel(logrus.ErrorLevel)
	case "ERR":
		logrus.SetLevel(logrus.ErrorLevel)
	case "WARNING":
		logrus.SetLevel(logrus.WarnLevel)
	case "NOTICE":
		logrus.SetLevel(logrus.InfoLevel)
	case "INFO":
		logrus.SetLevel(logrus.InfoLevel)
	case "DEBUG":
		logrus.SetLevel(logrus.DebugLevel)
	}

	var jwtSecret []byte
	if len(os.Getenv(JWT_TOKEN_SECRET)) == 0 {
		key := make([]byte, 8)
		_, err := rand.Read(key)
		if err != nil {
			log.Fatalf("Error generating random key: %v", err)
		}

		log.Print("missing JWT_TOKEN_SECRET environment variable, generating random key.")
		jwtSecret = key
	} else {
		jwtSecret = []byte(os.Getenv(JWT_TOKEN_SECRET))
	}

	jwtDurationStr := os.Getenv(JWT_TOKEN_DURATION)
	if len(jwtDurationStr) == 0 {
		jwtDurationStr = defaultJWTDurationStr
	}

	jwtDuration, err := strconv.Atoi(jwtDurationStr)
	if err != nil {
		log.Fatalf("error JWT_TOKEN_DURATION is not a number : %q", jwtDurationStr)
	}

	jwtSignMethod := os.Getenv(JWT_SIGNING_METHOD)
	if len(jwtSignMethod) == 0 {
		jwtSignMethod = defaultJWTSignMethod
	}

	frontendURL := "*" // default allow all
	if len(os.Getenv(ALLOWED_CORS_URL)) > 0 {
		frontendURL = os.Getenv(ALLOWED_CORS_URL)
	}

	if len(os.Getenv(ALLOWED_CORS_HEADERS)) > 0 {
		allowedCorsRequestHeaders = os.Getenv(ALLOWED_CORS_HEADERS)
	}

	listeningPort := ":8080"
	if len(os.Getenv(SERVER_PORT)) > 0 {
		listeningPort = ":" + os.Getenv(SERVER_PORT)
	}

	log.Printf("%q set to %v", JWT_TOKEN_DURATION, time.Duration(jwtDuration)*time.Hour)

	router := mux.NewRouter().StrictSlash(true)

	// default method not found handler
	router.NotFoundHandler = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			log.Printf("404 requesting %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			w.Header().Set(HeaderContentType, HeaderContentTypeValue)
			nf := RouteNotFound{Message: fmt.Sprintf("route not found %s", r.URL.Path)}
			err := json.NewEncoder(w).Encode(nf)
			if err != nil {
				log.Fatalf("error encoding error : %#v", err)
			}
		},
	)

	// default method not allowed handler
	router.MethodNotAllowedHandler = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			log.Printf("METHOD '%s' NOT ALLOWED requesting %q", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotAcceptable)
			w.Header().Set(HeaderContentType, HeaderContentTypeValue)
			nf := RouteNotFound{Message: fmt.Sprintf("route exists, but not found %s", r.URL.Path)}
			err := json.NewEncoder(w).Encode(nf)
			if err != nil {
				log.Fatalf("error encoding error : %#v", err)
			}
		},
	)

	// point your browser towards http://localhost:8080/docs/index.html
	router.PathPrefix("/docs").Handler(httpSwagger.WrapHandler)

	// Add the pprof routes if instructed
	if len(os.Getenv(ALLOW_PPROF)) > 0 && os.Getenv(ALLOW_PPROF) == "true" {
		router.HandleFunc("/debug/pprof/", pprof.Index)
		router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		router.HandleFunc("/debug/pprof/profile", pprof.Profile)
		router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		router.HandleFunc("/debug/pprof/trace", pprof.Trace)

		router.Handle("/debug/pprof/block", pprof.Handler("block"))
		router.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
		router.Handle("/debug/pprof/heap", pprof.Handler("heap"))
		router.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
	}

	ctx := context.Background()

	loginRepo := login.NewRepository()
	loginSvc := login.NewService(&loginRepo, jwtSecret, time.Duration(jwtDuration)*time.Hour)
	login.RegisterRoutes(router, &loginSvc, Logger, Recover)

	var group runner.Group
	group.Add(func() error {
		// listing all known routes
		_ = router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			t, err := route.GetPathTemplate()
			if err != nil {
				return nil
			}
			rx, err := route.GetPathRegexp()
			if err != nil {
				return nil
			}
			m, err := route.GetMethods()
			if err != nil {
				return nil
			}
			log.Printf("Template : %-40s Regexp: %-60s Method: %#v", t, rx, m)
			return nil
		})
		log.Printf("Starting local server on %s", listeningPort)

		corsHeaders := strings.Split(allowedCorsRequestHeaders, ",")
		return http.ListenAndServe(listeningPort, handlers.CORS(
			handlers.AllowedOrigins([]string{frontendURL}),
			handlers.AllowedMethods(allowedCorsMethods),
			handlers.AllowedHeaders(corsHeaders),
			handlers.ExposedHeaders(corsHeaders),
			handlers.AllowCredentials(),
		)(router))
	}, func(err error) {
		ctx.Done()
		log.Printf("stopping with error : %s", err)
	})

	if err := group.Wait(signal.WithTermination(ctx)); err != nil {
		return
	}
}
