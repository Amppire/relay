package domain

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrPolicyDenied = errors.New("access denied by policy")
)

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

// EvaluationContext captures the environment and identity attributes of an incoming access attempt
type EvaluationContext struct {
	ActorID       *uuid.UUID `json:"actor_id,omitempty"`
	Email         string     `json:"email,omitempty"`
	EmailDomain   string     `json:"email_domain,omitempty"`
	Authenticated bool       `json:"authenticated"`
	MFA           bool       `json:"mfa"`
	ClientIP      string     `json:"client_ip,omitempty"`
	CurrentTime   time.Time  `json:"current_time"`
	AccessCount   int64      `json:"access_count"`
}

// RuleDefinition defines the condition DSL for a policy
type RuleDefinition struct {
	Authenticated *bool      `json:"authenticated,omitempty"`
	MFA           *bool      `json:"mfa,omitempty"`
	EmailDomains  []string   `json:"email_domains,omitempty"`
	Emails        []string   `json:"emails,omitempty"`
	AllowedCIDRs  []string   `json:"allowed_cidrs,omitempty"`
	ExpiresBefore *time.Time `json:"expires_before,omitempty"`
	MaxAccesses   *int64     `json:"max_accesses,omitempty"`
}

// PolicyRule holds the structured allow/deny clauses
type PolicyRule struct {
	Allow RuleDefinition `json:"allow"`
}

// Policy entity
type Policy struct {
	ID          uuid.UUID  `json:"id"`
	WorkspaceID uuid.UUID  `json:"workspace_id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Version     int        `json:"version"`
	Rules       PolicyRule `json:"rules"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Evaluator evaluates access requests against a policy
type Evaluator interface {
	Evaluate(ctx EvaluationContext, policy *Policy) (Decision, string, error)
}

// NativeEvaluator implements a deterministic, Default-DENY access evaluator
type NativeEvaluator struct{}

func NewNativeEvaluator() *NativeEvaluator {
	return &NativeEvaluator{}
}

func (e *NativeEvaluator) Evaluate(ctx EvaluationContext, policy *Policy) (Decision, string, error) {
	if policy == nil {
		// No policy attached -> Default Allow
		return DecisionAllow, "no policy attached", nil
	}

	allow := policy.Rules.Allow

	// 1. Authentication check
	if allow.Authenticated != nil && *allow.Authenticated && !ctx.Authenticated {
		return DecisionDeny, "authentication required", nil
	}

	// 2. MFA check
	if allow.MFA != nil && *allow.MFA && !ctx.MFA {
		return DecisionDeny, "mfa verification required", nil
	}

	// 3. Email domain restriction
	if len(allow.EmailDomains) > 0 {
		matched := false
		ctxDomain := strings.ToLower(ctx.EmailDomain)
		if ctxDomain == "" && strings.Contains(ctx.Email, "@") {
			parts := strings.Split(ctx.Email, "@")
			ctxDomain = strings.ToLower(parts[1])
		}

		for _, d := range allow.EmailDomains {
			if strings.EqualFold(d, ctxDomain) {
				matched = true
				break
			}
		}
		if !matched {
			return DecisionDeny, "email domain not permitted", nil
		}
	}

	// 4. Specific email allowlist
	if len(allow.Emails) > 0 {
		matched := false
		for _, em := range allow.Emails {
			if strings.EqualFold(em, ctx.Email) {
				matched = true
				break
			}
		}
		if !matched {
			return DecisionDeny, "email not permitted", nil
		}
	}

	// 5. Network CIDR allowlist
	if len(allow.AllowedCIDRs) > 0 {
		clientIP := net.ParseIP(ctx.ClientIP)
		if clientIP == nil {
			return DecisionDeny, "invalid client ip address", nil
		}

		matched := false
		for _, cidr := range allow.AllowedCIDRs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err == nil && ipNet.Contains(clientIP) {
				matched = true
				break
			}
		}
		if !matched {
			return DecisionDeny, "client ip not within allowed cidr ranges", nil
		}
	}

	// 6. Time window limit
	if allow.ExpiresBefore != nil && !ctx.CurrentTime.Before(*allow.ExpiresBefore) {
		return DecisionDeny, "access window has closed", nil
	}

	// 7. Maximum accesses check
	if allow.MaxAccesses != nil && ctx.AccessCount >= *allow.MaxAccesses {
		return DecisionDeny, "maximum access limit exceeded", nil
	}

	return DecisionAllow, "policy requirements satisfied", nil
}

// ParsePolicyRules decodes JSON bytes into structured PolicyRule
func ParsePolicyRules(rawJSON string) (PolicyRule, error) {
	var r PolicyRule
	if strings.TrimSpace(rawJSON) == "" || rawJSON == "{}" {
		return r, nil
	}
	err := json.Unmarshal([]byte(rawJSON), &r)
	return r, err
}
