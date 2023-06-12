package login

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

const (
	LoginRoute = "/login"
)

type Service interface {
	Sign(clientID, clientSecret string) (*TokenResponse, error)
}

func issueToken(svc Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprintf(w, "Unauthorized")
			log.Printf("Unauthorized attempt detected with request : %#v", r)
			return
		}

		response, err := svc.Sign(clientID, clientSecret)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintf(w, "Failed to sign the token")
			log.Printf("Internal server error : %#v", err)
			return
		}

		// Send the token response as JSON
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("error encoding json : %#v", err)
		}
	})
}

func RegisterRoutes(router *mux.Router, svc Service, logger func(inner http.Handler, name string) http.Handler, recoverer func(next http.Handler) http.Handler) {
	router.Methods(http.MethodPost).
		Path(LoginRoute).
		Name("Login").
		Handler(
			recoverer(
				logger(
					issueToken(svc), LoginRoute,
				),
			),
		)
}
