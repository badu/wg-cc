package login

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

const (
	TokenRoute      = "/v1/oauth2/token"
	ListRoute       = "/v1/oauth2/keys"
	IntrospectRoute = "/v1/oauth2/introspect"
)

type Service interface {
	Sign(clientID, clientSecret string) (*TokenResponse, error)
	DecodeJWTToken(tokenString string) (*jwt.Token, error)
	ListKeys() KeysResponse
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

// ListRSAKeys godoc
// @ID list-keys
// @Summary endpoint to list the signing keys (rfc7517)
// @Description
// @Tags token
// @Produce json
// @Security
// @Success 200 {object} KeysResponse
// @Failure 400,401
// @Failure 500
// @Router /v1/oauth2/keys [get]
func ListRSAKeys(svc Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "Bad request")
			return
		}

		// Extract token from request headers or cookies
		tokenString := r.Header.Get("Authorization")

		if len(tokenString) == 0 {
			cookie, err := r.Cookie("jwt_token")
			if err == nil {
				tokenString = cookie.Value
			}
		}

		if len(tokenString) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Unauthorized")
			return
		}

		// Parse and validate the token
		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)

		// use service to decode our token
		token, err := svc.DecodeJWTToken(tokenString)

		if err != nil || !token.Valid {
			log.Printf("invalid token or error : %#v\n%s", err, tokenString)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Unauthorized")
			return
		}

		response := svc.ListKeys()

		// Send the keys response as JSON
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
}

// Introspect godoc
// @ID introspect-jwt
// @Summary Introspection endpoint (rfc7662) to introspect the issued JWT Access Tokens
// @Description
// @Tags token
// @Produce json
// @Security
// @Success 200 {object} IntrospectionResponse
// @Failure 400,401
// @Failure 500
// @Router /v1/oauth2/introspect [get]
func Introspect(svc Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "Bad request")
			return
		}

		// Extract token from request headers or cookies
		tokenString := r.Header.Get("Authorization")

		if len(tokenString) == 0 {
			cookie, err := r.Cookie("jwt_token")
			if err == nil {
				tokenString = cookie.Value
			}
		}

		if len(tokenString) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Unauthorized")
			return
		}

		// Parse and validate the token
		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)

		// use service to decode our token
		token, err := svc.DecodeJWTToken(tokenString)

		var response IntrospectionResponse
		if err == nil {
			// Verify if the token is valid and not expired
			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				response = IntrospectionResponse{Active: true}
				if scope, has := claims["scope"]; has {
					if scopeStr, ok := scope.(string); ok {
						response.Scope = scopeStr
					}
				}
				if expires, has := claims["exp"]; has {
					if expireFloat, ok := expires.(float64); ok {
						response.ExpiresAt = int64(expireFloat)
					}
				}
			}
		}

		// Send the response as JSON
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
}

func RegisterRoutes(
	router *mux.Router,
	svc Service,
	logger func(inner http.Handler, name string) http.Handler,
	recoverer func(next http.Handler) http.Handler,
) {
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

	router.Methods(http.MethodGet).
		Path(ListRoute).
		Name("ListRoute").
		Handler(
			recoverer(
				logger(
					ListRSAKeys(svc), ListRoute,
				),
			),
		)

	router.Methods(http.MethodGet).
		Path(IntrospectRoute).
		Name("IntrospectRoute").
		Handler(
			recoverer(
				logger(
					Introspect(svc), IntrospectRoute,
				),
			),
		)

}
