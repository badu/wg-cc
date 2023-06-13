package login

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

const (
	TokenRoute = "/v1/oauth2/token"
)

type Service interface {
	Sign(clientID, clientSecret string) (*TokenResponse, error)
}

func IssueToken(svc Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "Bad request")
			return
		}

		grantType := r.Form.Get("grant_type")
		switch grantType {
		case "client_credentials":
			clientID := r.Form.Get("client_id")
			clientSecret := r.Form.Get("client_secret")
			response, err := svc.Sign(clientID, clientSecret)
			if err != nil {
				if errors.Is(err, NotFoundError) {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = fmt.Fprintf(w, "Unauthorized")
					log.Printf("Client id %s not found.", clientID)
					return
				}

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
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprintf(w, "Unauthorized")
			log.Printf("Unauthorized attempt detected with request : %#v", r)

		}

	})
}

func RegisterRoutes(router *mux.Router, svc Service, logger func(inner http.Handler, name string) http.Handler, recoverer func(next http.Handler) http.Handler) {
	router.Methods(http.MethodPost).
		Path(TokenRoute).
		Name("TokenRoute").
		Handler(
			recoverer(
				logger(
					IssueToken(svc), TokenRoute,
				),
			),
		)
}
