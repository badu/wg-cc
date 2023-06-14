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
	OnboardingRoute = "/v1/oauth2/onboard"
)

var (
	// pre-allocated errors
	unauthorized = ErrorResponse{
		Code:    http.StatusUnauthorized,
		Message: "Unauthorized",
	}
	badRequest = ErrorResponse{
		Code:    http.StatusBadRequest,
		Message: "Bad request",
	}
	internal = ErrorResponse{
		Code:    http.StatusInternalServerError,
		Message: "Failed to sign the token, see server logs",
	}
)

type Service interface {
	Sign(clientID, clientSecret string) (*TokenResponse, error)
	DecodeJWTToken(tokenString string) (*jwt.Token, error)
	ListKnownSigningKeys() (*KeysResponse, error)
	GenerateAndSavePrivateKey(totpKey, keyName string) error
	OnboardNewClient(totpKey, clientID, clientSecret, keyName string) error
}

// IssueToken godoc
// @Summary Issues JWT Access Tokens (rfc7519) using Client Credentials Grant with Basic Authentication (rfc6749)
// @ID create-token
// @Description This endpoint issues JWT Access Tokens using the Client Credentials Grant with Basic Authentication.
// @Tags token
// @Accept x-www-form-urlencoded
// @Produce json
// @Success 200 {object} TokenResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Param grant_type formData string true "grant_type" default(client_credentials)
// @Param client_id formData string true "client_id" default(test)
// @Param client_secret formData string true "client_secret" default(test)
// @Router /v1/oauth2/token [post]
func IssueToken(svc Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "Bad request : must accept application/json")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		jsonEncoder := json.NewEncoder(w)

		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			w.WriteHeader(badRequest.Code)
			if err := jsonEncoder.Encode(badRequest); err != nil {
				log.Printf("Error encoding JSON: %#v", err)
			}
			return
		}

		if err := r.ParseForm(); err != nil {
			log.Printf("Failed to parse form data : %#v", err)
			w.WriteHeader(badRequest.Code)
			if err := jsonEncoder.Encode(badRequest); err != nil {
				log.Printf("Error encoding JSON: %#v", err)
			}
			return
		}

		grantType := r.Form.Get("grant_type")
		switch grantType {
		case "client_credentials":
			clientID := r.Form.Get("client_id")
			clientSecret := r.Form.Get("client_secret")
			response, err := svc.Sign(clientID, clientSecret)

			// err is nil => success
			if err == nil {
				if err := jsonEncoder.Encode(response); err != nil {
					log.Printf("Error encoding JSON: %#v", err)
				}
				return
			}

			// err present (not found in database ?)
			if errors.Is(err, sql.ErrNoRows) {
				log.Printf("Client id %q was not found", clientID)
				w.WriteHeader(unauthorized.Code)
				if err := jsonEncoder.Encode(unauthorized); err != nil {
					log.Printf("Error encoding JSON: %#v", err)
				}
				return
			}

			// err present (bad password ?)
			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				log.Printf("Client id %q provided bad password", clientID)
				w.WriteHeader(unauthorized.Code)
				if err := jsonEncoder.Encode(unauthorized); err != nil {
					log.Printf("Error encoding JSON: %#v", err)
				}
				return
			}

			// err present (other error)
			w.WriteHeader(internal.Code)
			log.Printf("Internal server error: %#v", err)
			if err := jsonEncoder.Encode(internal); err != nil {
				log.Printf("Error encoding JSON: %#v", err)
			}
		default:
			log.Printf("Unauthorized attempt detected with request: %#v", r)
			w.WriteHeader(unauthorized.Code)
			if err := jsonEncoder.Encode(unauthorized); err != nil {
				log.Printf("Error encoding JSON: %#v", err)
			}
		}
	})
}

// Extract token from request headers or cookies
func getTokenFromRequest(r *http.Request) string {
	tokenString := r.Header.Get("Authorization")

	if len(tokenString) == 0 {
		// attempt to find it as cookie
		cookie, err := r.Cookie("jwt_token")
		if err == nil {
			tokenString = cookie.Value
		}
	}

	if len(tokenString) > 0 {
		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
	}

	return tokenString
}

// ListKnownSigningKeys godoc
// @Summary Endpoint to list the signing keys (rfc7517)
// @ID list-keys
// @Description This endpoint lists the signing keys.
// @Tags token
// @Produce json
// @Security BearerAuth
// @Success 200 {object} KeysResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /v1/oauth2/keys [get]
func ListKnownSigningKeys(svc Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "Bad request")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		jsonEncoder := json.NewEncoder(w)

		tokenString := getTokenFromRequest(r)
		if len(tokenString) == 0 {
			log.Printf("Token not found in request")
			w.WriteHeader(unauthorized.Code)
			if err := jsonEncoder.Encode(unauthorized); err != nil {
				log.Printf("Error encoding JSON: %#v", err)
			}
			return
			return
		}

		// use service to decode our token
		token, err := svc.DecodeJWTToken(tokenString)

		if err != nil || !token.Valid {
			log.Printf("invalid token or error : %#v\n%s", err, tokenString)
			w.WriteHeader(unauthorized.Code)
			if err := jsonEncoder.Encode(unauthorized); err != nil {
				log.Printf("Error encoding JSON: %#v", err)
			}
			return
		}

		response, err := svc.ListKnownSigningKeys()
		if err != nil {
			// err present (other error)
			w.WriteHeader(internal.Code)
			log.Printf("error listing signing keys: %#v", err)
			if err := jsonEncoder.Encode(internal); err != nil {
				log.Printf("Error encoding JSON: %#v", err)
			}
		}

		// Send the keys response as JSON
		if err := jsonEncoder.Encode(response); err != nil {
			log.Printf("Error encoding JSON: %#v", err)
		}
	})
}

// Introspect godoc
// @Summary Introspection endpoint (rfc7662) to introspect the issued JWT Access Tokens
// @ID introspect-jwt
// @Description This endpoint allows introspection of the issued JWT Access Tokens.
// @Tags token
// @Produce json
// @Security BearerAuth
// @Success 200 {object} IntrospectionResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /v1/oauth2/introspect [get]
// @Router /v1/oauth2/introspect [post]
func Introspect(svc Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "Bad request")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		jsonEncoder := json.NewEncoder(w)

		tokenString := getTokenFromRequest(r)
		if len(tokenString) == 0 {
			log.Printf("Token not found in request")
			w.WriteHeader(unauthorized.Code)
			if err := jsonEncoder.Encode(unauthorized); err != nil {
				log.Printf("Error encoding JSON: %#v", err)
			}
			return
			return
		}

		// use service to decode our token
		token, err := svc.DecodeJWTToken(tokenString)

		if err != nil || !token.Valid {
			log.Printf("invalid token or error : %#v\n%s", err, tokenString)
			w.WriteHeader(unauthorized.Code)
			if err := jsonEncoder.Encode(unauthorized); err != nil {
				log.Printf("Error encoding JSON: %#v", err)
			}
			return
		}

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

		// Send the keys response as JSON
		if err := jsonEncoder.Encode(response); err != nil {
			log.Printf("Error encoding JSON: %#v", err)
		}
	})
}

// Onboarding godoc
// @Summary Facilitates the creation of signing keys and onboarding new clients (client_id, client_secret and signing key pairs)
// @ID declare-clients-and-keys
// @Description This endpoint helps local tests, by creating signing keys and declaring new clients
// @Tags token
// @Accept x-www-form-urlencoded
// @Success 202
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Param totp formData string true "totp code"
// @Param operation_type formData string true "operation_type can be create_key (should provide key_name) and create_client (should provide client_id, client_secret and associated key_name)." default(client_credentials)
// @Param client_id formData string false "client_id" default(test)
// @Param client_secret formData string false "client_secret" default(test)
// @Param key_name formData string true "key_name" default(my_key)
// @Router /v1/oauth2/onboard [post]
func Onboarding(svc Service) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, "Bad request : must accept application/json")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		jsonEncoder := json.NewEncoder(w)

		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			w.WriteHeader(badRequest.Code)
			if err := jsonEncoder.Encode(badRequest); err != nil {
				log.Printf("Error encoding JSON: %#v", err)
			}
			return
		}

		if err := r.ParseForm(); err != nil {
			log.Printf("Failed to parse form data : %#v", err)
			w.WriteHeader(badRequest.Code)
			if err := jsonEncoder.Encode(badRequest); err != nil {
				log.Printf("Error encoding JSON: %#v", err)
			}
			return
		}

		operation := r.Form.Get("operation_type")
		switch operation {
		case "create_key":
			totpKey := r.Form.Get("totp")
			keyName := r.Form.Get("key_name")
			err := svc.GenerateAndSavePrivateKey(totpKey, keyName)
			if err != nil {
				log.Printf("there was an error while trying to save the new signing key : %#v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusAccepted)
		case "create_client":
			totpKey := r.Form.Get("totp")
			keyName := r.Form.Get("key_name")
			clientID := r.Form.Get("client_id")
			clientSecret := r.Form.Get("client_secret")
			err := svc.OnboardNewClient(totpKey, clientID, clientSecret, keyName)
			if err != nil {
				log.Printf("there was an error while trying to save the new signing key : %#v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusAccepted)
		default:
			log.Printf("Unauthorized attempt detected with request: %#v", r)
			w.WriteHeader(unauthorized.Code)
			if err := jsonEncoder.Encode(unauthorized); err != nil {
				log.Printf("Error encoding JSON: %#v", err)
			}
		}
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
					ListKnownSigningKeys(svc), ListRoute,
				),
			),
		)

	// rfc7662 states it should support both POST and GET verbs
	router.Methods(http.MethodGet, http.MethodPost).
		Path(IntrospectRoute).
		Name("IntrospectRoute").
		Handler(
			recoverer(
				logger(
					Introspect(svc), IntrospectRoute,
				),
			),
		)

	router.Methods(http.MethodPost).
		Path(OnboardingRoute).
		Name("OnboardingRoute").
		Handler(
			recoverer(
				logger(
					Onboarding(svc), OnboardingRoute,
				),
			),
		)

}
