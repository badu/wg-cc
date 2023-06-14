// Package docs GENERATED BY THE COMMAND ABOVE; DO NOT EDIT
// This file was generated by swaggo/swag
package docs

import (
	"bytes"
	"encoding/json"
	"strings"
	"text/template"

	"github.com/swaggo/swag"
)

var doc = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "termsOfService": "http://swagger.io/terms/",
        "contact": {},
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/v1/oauth2/introspect": {
            "get": {
                "security": [
                    {
                        "BearerAuth": []
                    }
                ],
                "description": "This endpoint allows introspection of the issued JWT Access Tokens.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "token"
                ],
                "summary": "Introspection endpoint (rfc7662) to introspect the issued JWT Access Tokens",
                "operationId": "introspect-jwt",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/login.IntrospectionResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/login.ErrorResponse"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/login.ErrorResponse"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/login.ErrorResponse"
                        }
                    }
                }
            },
            "post": {
                "security": [
                    {
                        "BearerAuth": []
                    }
                ],
                "description": "This endpoint allows introspection of the issued JWT Access Tokens.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "token"
                ],
                "summary": "Introspection endpoint (rfc7662) to introspect the issued JWT Access Tokens",
                "operationId": "introspect-jwt",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/login.IntrospectionResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/login.ErrorResponse"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/login.ErrorResponse"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/login.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/v1/oauth2/keys": {
            "get": {
                "security": [
                    {
                        "BearerAuth": []
                    }
                ],
                "description": "This endpoint lists the signing keys.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "token"
                ],
                "summary": "Endpoint to list the signing keys (rfc7517)",
                "operationId": "list-keys",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/login.KeysResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/login.ErrorResponse"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/login.ErrorResponse"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/login.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/v1/oauth2/token": {
            "post": {
                "description": "This endpoint issues JWT Access Tokens using the Client Credentials Grant with Basic Authentication.",
                "consumes": [
                    "application/x-www-form-urlencoded"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "token"
                ],
                "summary": "Issues JWT Access Tokens (rfc7519) using Client Credentials Grant with Basic Authentication (rfc6749)",
                "operationId": "create-token",
                "parameters": [
                    {
                        "type": "string",
                        "default": "client_credentials",
                        "description": "grant_type",
                        "name": "grant_type",
                        "in": "formData",
                        "required": true
                    },
                    {
                        "type": "string",
                        "default": "test",
                        "description": "client_id",
                        "name": "client_id",
                        "in": "formData",
                        "required": true
                    },
                    {
                        "type": "string",
                        "default": "test",
                        "description": "client_secret",
                        "name": "client_secret",
                        "in": "formData",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/login.TokenResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/login.ErrorResponse"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/login.ErrorResponse"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "$ref": "#/definitions/login.ErrorResponse"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "login.ErrorResponse": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "integer"
                },
                "error": {
                    "type": "string"
                }
            }
        },
        "login.IntrospectionResponse": {
            "type": "object",
            "properties": {
                "active": {
                    "type": "boolean"
                },
                "exp": {
                    "type": "integer"
                },
                "scope": {
                    "type": "string"
                }
            }
        },
        "login.KeysResponse": {
            "type": "object",
            "properties": {
                "keys": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/login.SignKey"
                    }
                }
            }
        },
        "login.SignKey": {
            "type": "object",
            "properties": {
                "algorithm": {
                    "type": "string"
                },
                "key_id": {
                    "type": "string"
                },
                "public_key": {
                    "type": "string"
                },
                "use": {
                    "type": "string"
                }
            }
        },
        "login.TokenResponse": {
            "type": "object",
            "properties": {
                "access_token": {
                    "type": "string"
                },
                "expires_in": {
                    "type": "integer"
                },
                "token_type": {
                    "type": "string"
                }
            }
        }
    },
    "securityDefinitions": {
        "BasicAuth": {
            "type": "basic"
        },
        "BearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header"
        }
    }
}`

type swaggerInfo struct {
	Version     string
	Host        string
	BasePath    string
	Schemes     []string
	Title       string
	Description string
}

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = swaggerInfo{
	Version:     "1.0",
	Host:        "localhost:8080",
	BasePath:    "",
	Schemes:     []string{},
	Title:       "OAuth 2 Server",
	Description: "This is API server.",
}

type s struct{}

func (s *s) ReadDoc() string {
	sInfo := SwaggerInfo
	sInfo.Description = strings.Replace(sInfo.Description, "\n", "\\n", -1)

	t, err := template.New("swagger_info").Funcs(template.FuncMap{
		"marshal": func(v interface{}) string {
			a, _ := json.Marshal(v)
			return string(a)
		},
		"escape": func(v interface{}) string {
			// escape tabs
			str := strings.Replace(v.(string), "\t", "\\t", -1)
			// replace " with \", and if that results in \\", replace that with \\\"
			str = strings.Replace(str, "\"", "\\\"", -1)
			return strings.Replace(str, "\\\\\"", "\\\\\\\"", -1)
		},
	}).Parse(doc)
	if err != nil {
		return doc
	}

	var tpl bytes.Buffer
	if err := t.Execute(&tpl, sInfo); err != nil {
		return doc
	}

	return tpl.String()
}

func init() {
	swag.Register(swag.Name, &s{})
}
