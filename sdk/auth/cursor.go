package auth

import (
	"context"
	"fmt"
	"time"

	cursorauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/cursor"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/browser"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// CursorAuthenticator implements OAuth PKCE login for Cursor.
type CursorAuthenticator struct{}

// NewCursorAuthenticator constructs a new Cursor authenticator.
func NewCursorAuthenticator() Authenticator {
	return &CursorAuthenticator{}
}

// Provider returns the provider key for cursor.
func (CursorAuthenticator) Provider() string {
	return "cursor"
}

// RefreshLead returns the time before expiry when a refresh should be attempted.
func (CursorAuthenticator) RefreshLead() *time.Duration {
	d := 10 * time.Minute
	return &d
}

// Login initiates the Cursor PKCE authentication flow.
func (a CursorAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cursor auth: configuration is required")
	}
	if opts == nil {
		opts = &LoginOptions{}
	}

	// Generate PKCE auth parameters
	authParams, err := cursorauth.GenerateAuthParams()
	if err != nil {
		return nil, fmt.Errorf("cursor: failed to generate auth params: %w", err)
	}

	// Display the login URL. These four prompts are user-facing CLI output
	// for a one-shot login command, so they go to stdout via fmt (bypassing
	// logrus) -- otherwise logging-to-file:true would hide them inside
	// ~/.cli-proxy-api/logs/main.log and the user would see the program
	// appear to hang (issue #122). The browser-open warning stays on logrus
	// because it is a diagnostic, not a prompt.
	fmt.Println("Starting Cursor authentication...")
	fmt.Printf("Please visit this URL to log in: %s\n", authParams.LoginURL)

	// Try to open the browser automatically
	if !opts.NoBrowser {
		if browser.IsAvailable() {
			if errOpen := browser.OpenURL(authParams.LoginURL); errOpen != nil {
				log.Warnf("Failed to open browser automatically: %v", errOpen)
			}
		}
	}

	fmt.Println("Waiting for Cursor authorization...")

	// Poll for the auth result
	tokens, err := cursorauth.PollForAuth(ctx, authParams.UUID, authParams.Verifier)
	if err != nil {
		return nil, fmt.Errorf("cursor: authentication failed: %w", err)
	}

	expiresAt := cursorauth.GetTokenExpiry(tokens.AccessToken)

	// Auto-identify account from JWT sub claim
	sub := cursorauth.ParseJWTSub(tokens.AccessToken)
	subHash := cursorauth.SubToShortHash(sub)

	fmt.Println("Cursor authentication successful!")

	metadata := map[string]any{
		"type":          "cursor",
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"expires_at":    expiresAt.Format(time.RFC3339),
		"timestamp":     time.Now().UnixMilli(),
	}
	if sub != "" {
		metadata["sub"] = sub
	}

	fileName := cursorauth.CredentialFileName("", subHash)

	return &coreauth.Auth{
		ID:       fileName,
		Provider: a.Provider(),
		FileName: fileName,
		Label:    cursorauth.DisplayLabel("", subHash),
		Metadata: metadata,
	}, nil
}
