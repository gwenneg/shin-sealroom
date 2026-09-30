package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"
)

const (
	googleTokenURL = "https://oauth2.googleapis.com/token"
	googleScope    = "https://www.googleapis.com/auth/cloud-platform"
)

// googleCredentials holds the fields of the two kinds of Application
// Default Credentials the proxy accepts.
type googleCredentials struct {
	Type string `json:"type"`
	// authorized_user, from gcloud auth application-default login
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	// service_account
	ClientEmail  string `json:"client_email"`
	PrivateKey   string `json:"private_key"`
	PrivateKeyID string `json:"private_key_id"`
	TokenURI     string `json:"token_uri"`
}

// GoogleTokens returns a source of Google access tokens minted from the
// user's credentials: a login from gcloud auth application-default login, or
// a service account key. It is built once, independent of any request, and
// refreshes its token as it expires. Its own requests to Google go through
// client. Only the token endpoint the credentials name is used, and for a
// service account it must be Google's.
func GoogleTokens(credentials []byte, client *http.Client) (oauth2.TokenSource, error) {
	var c googleCredentials
	if err := json.Unmarshal(credentials, &c); err != nil {
		return nil, fmt.Errorf("Google credentials: %w", err)
	}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)
	switch c.Type {
	case "authorized_user":
		if c.ClientID == "" || c.ClientSecret == "" || c.RefreshToken == "" {
			return nil, errors.New("Google credentials: a user login without its client or refresh token")
		}
		cfg := &oauth2.Config{
			ClientID: c.ClientID, ClientSecret: c.ClientSecret, Scopes: []string{googleScope},
			Endpoint: oauth2.Endpoint{TokenURL: googleTokenURL, AuthStyle: oauth2.AuthStyleInParams},
		}
		return cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: c.RefreshToken}), nil
	case "service_account":
		if c.ClientEmail == "" || c.PrivateKey == "" {
			return nil, errors.New("Google credentials: a service account without its email or key")
		}
		if c.TokenURI != "" && c.TokenURI != googleTokenURL {
			return nil, fmt.Errorf("Google credentials: token endpoint %q is not Google's", c.TokenURI)
		}
		cfg := &jwt.Config{
			Email: c.ClientEmail, PrivateKey: []byte(c.PrivateKey), PrivateKeyID: c.PrivateKeyID,
			Scopes: []string{googleScope}, TokenURL: googleTokenURL,
		}
		return cfg.TokenSource(ctx), nil
	}
	return nil, fmt.Errorf("Google credentials of type %q: want a user login or a service account key", c.Type)
}
