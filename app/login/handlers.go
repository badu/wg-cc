package login

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

const (
	TokenRoute = "/v1/oauth2/token"
)

type Service interface {
	Sign(clientID, clientSecret string) (*TokenResponse, error)
}

// IssueToken godoc
// @ID create-token
// @Summary issues JWT Access Tokens (rfc7519) using Client Credentials Grant with Basic Authentication (rfc6749)
// @Description
// @Tags token
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Success 200 {object} TokenResponse
// @Failure 400,401
// @Failure 500
// @Router /v1/oauth2/token [post]
func IssueToken(svc Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "Bad request")
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form data", http.StatusBadRequest)
			return
		}

		grantType := r.Form.Get("grant_type")
		switch grantType {
		case "client_credentials":
			clientID := r.Form.Get("client_id")
			clientSecret := r.Form.Get("client_secret")
			response, err := svc.Sign(clientID, clientSecret)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = fmt.Fprintf(w, "Unauthorized")
					log.Printf("Client id %q not found", clientID)
					return
				}

				if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = fmt.Fprintf(w, "Unauthorized")
					log.Printf("Client id %q provided bad password", clientID)
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
