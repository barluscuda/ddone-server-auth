package dexbotkiller

import "strings"

type signal struct {
	reason string
	score  float64
}

func clientQualitySignals(req Request, policy Policy) []signal {
	var signals []signal

	if strings.TrimSpace(req.Client.UserAgent) == "" {
		signals = append(signals, signal{reason: "missing_user_agent", score: policy.MissingUserAgentScore})
	} else if suspiciousUserAgent(req.Client.UserAgent) {
		signals = append(signals, signal{reason: "suspicious_user_agent", score: policy.SuspiciousAgentScore})
	}

	if req.Client.DeviceID == "" || !req.Client.HasDeviceCookie {
		signals = append(signals, signal{reason: "missing_device_cookie", score: policy.MissingDeviceScore})
	}

	contentType := strings.ToLower(strings.TrimSpace(req.Client.ContentType))
	if req.Action == FlowActionStart && contentType != "" && !strings.HasPrefix(contentType, "application/json") {
		signals = append(signals, signal{reason: "invalid_content_type", score: policy.InvalidContentTypeScore})
	}

	return signals
}

func suspiciousUserAgent(userAgent string) bool {
	normalized := strings.ToLower(strings.TrimSpace(userAgent))
	if normalized == "" {
		return false
	}

	suspiciousMarkers := []string{
		"bot",
		"crawler",
		"spider",
		"curl",
		"wget",
		"python-requests",
		"httpclient",
		"go-http-client",
	}
	for _, marker := range suspiciousMarkers {
		if strings.Contains(normalized, marker) {
			return true
		}
	}

	return false
}
