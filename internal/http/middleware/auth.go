package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/relay/relay/internal/core/domain"
	"github.com/relay/relay/internal/core/services"
)

type contextKey string

const (
	APIKeyContextKey contextKey = "relay_api_key"
)

type AuthMiddleware struct {
	authService *services.AuthService
}

func NewAuthMiddleware(authService *services.AuthService) *AuthMiddleware {
	return &AuthMiddleware{authService: authService}
}

// RequireScope validates the Bearer token and ensures the requested scope is permitted.
func (m *AuthMiddleware) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				http.Error(w, `{"error":"invalid authorization format, expected Bearer <token>"}`, http.StatusUnauthorized)
				return
			}

			token := parts[1]
			apiKey, err := m.authService.Authenticate(r.Context(), token)
			if err != nil {
				http.Error(w, `{"error":"invalid or expired api key"}`, http.StatusUnauthorized)
				return
			}

			if !apiKey.HasScope(scope) {
				http.Error(w, `{"error":"forbidden: insufficient scope"}`, http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), APIKeyContextKey, apiKey)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalAuth attaches the APIKey to the context if present, without blocking requests.
func (m *AuthMiddleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
				if apiKey, err := m.authService.Authenticate(r.Context(), parts[1]); err == nil {
					ctx := context.WithValue(r.Context(), APIKeyContextKey, apiKey)
					r = r.WithContext(ctx)
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func GetAPIKeyFromContext(ctx context.Context) *domain.APIKey {
	if val, ok := ctx.Value(APIKeyContextKey).(*domain.APIKey); ok {
		return val
	}
	return nil
}
