package caddyoidcgate

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
)

var errGroupClaimMissing = errors.New("group claim missing")

// stringList decodes a claim that providers emit either as a JSON array
// (Keycloak, Authentik) or as one delimiter-separated string (GitLab,
// plain OIDC). Unsupported shapes are an error rather than a silent deny.
type stringList []string

func (s *stringList) UnmarshalJSON(b []byte) error {
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	switch v := raw.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		*s = out
	case string:
		*s = strings.Fields(v)
	default:
		return fmt.Errorf("unsupported claim shape %T", raw)
	}
	return nil
}

// checkGroups enforces allowed_groups. A configured allow-list with a missing
// claim means the provider is not sending what the operator asked for, so it
// denies and logs instead of quietly letting everyone in.
func (h *Handler) checkGroups(idToken *oidc.IDToken, remoteAddr string) error {
	if len(h.AllowedGroups) == 0 {
		return nil
	}

	claims := map[string]json.RawMessage{}
	if err := idToken.Claims(&claims); err != nil {
		h.logger.Warn("failed to decode group claim", zap.String("sub", idToken.Subject), zap.Error(err))
		return err
	}

	raw, ok := claims[h.GroupsClaim]
	if !ok {
		h.logger.Warn("allowed_groups is set but the provider sends no such claim",
			zap.String("sub", idToken.Subject),
			zap.String("claim", h.GroupsClaim),
			zap.String("remote_ip", remoteAddr))
		return errGroupClaimMissing
	}

	var groups stringList
	if err := json.Unmarshal(raw, &groups); err != nil {
		h.logger.Warn("group claim has an unsupported shape",
			zap.String("sub", idToken.Subject),
			zap.String("claim", h.GroupsClaim),
			zap.Error(err))
		return err
	}

	for _, g := range groups {
		if slices.Contains(h.AllowedGroups, g) {
			return nil
		}
	}

	h.logger.Warn("user not in an allowed group",
		zap.String("sub", idToken.Subject),
		zap.String("claim", h.GroupsClaim),
		zap.Strings("groups", groups),
		zap.String("remote_ip", remoteAddr))
	return errors.New("user not in an allowed group")
}
