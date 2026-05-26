package middleware

import (
	"crypto/rand"
	"ddone-server-auth/internal/application/dexbotkiller"
	"encoding/base64"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const defaultDeviceIDBytes = 16

type ClientContextConfig struct {
	DeviceCookieName     string
	DeviceCookieMaxAge   time.Duration
	DeviceCookieSecure   bool
	DeviceCookieSameSite http.SameSite
}

func ClientContext(config ClientContextConfig, hasher dexbotkiller.Hasher) gin.HandlerFunc {
	if config.DeviceCookieName == "" {
		config.DeviceCookieName = "ddone_device"
	}
	if config.DeviceCookieMaxAge <= 0 {
		config.DeviceCookieMaxAge = 720 * time.Hour
	}

	return func(c *gin.Context) {
		deviceID, hasDeviceCookie := readSignedDeviceCookie(c, config.DeviceCookieName, hasher)
		if deviceID == "" {
			generatedDeviceID, err := generateDeviceID()
			if err == nil {
				deviceID = generatedDeviceID
				writeSignedDeviceCookie(c, config, hasher, deviceID)
			}
		}

		clientContext := dexbotkiller.ClientContext{
			IP:              c.ClientIP(),
			Subnet:          subnetForIP(c.ClientIP()),
			UserAgent:       normalizeHeader(c.Request.UserAgent(), 256),
			DeviceID:        deviceID,
			HasDeviceCookie: hasDeviceCookie,
			AcceptLanguage:  normalizeHeader(c.GetHeader("Accept-Language"), 128),
			ContentType:     normalizeHeader(c.GetHeader("Content-Type"), 128),
			Timestamp:       time.Now().UTC(),
		}
		ctx := dexbotkiller.ContextWithClientContext(c.Request.Context(), clientContext)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

func readSignedDeviceCookie(c *gin.Context, cookieName string, hasher dexbotkiller.Hasher) (string, bool) {
	raw, err := c.Cookie(cookieName)
	if err != nil {
		return "", false
	}

	deviceID, signature, ok := strings.Cut(raw, ".")
	if !ok || deviceID == "" || signature == "" {
		return "", false
	}
	if !hasher.ValidSignature(deviceID, signature) {
		return "", false
	}

	return deviceID, true
}

func writeSignedDeviceCookie(c *gin.Context, config ClientContextConfig, hasher dexbotkiller.Hasher, deviceID string) {
	sameSite := config.DeviceCookieSameSite
	if sameSite == 0 {
		sameSite = http.SameSiteLaxMode
	}

	c.SetSameSite(sameSite)
	c.SetCookie(
		config.DeviceCookieName,
		deviceID+"."+hasher.Sign(deviceID),
		int(config.DeviceCookieMaxAge/time.Second),
		"/",
		"",
		config.DeviceCookieSecure,
		true,
	)
}

func generateDeviceID() (string, error) {
	bytes := make([]byte, defaultDeviceIDBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func subnetForIP(rawIP string) string {
	addr, err := netip.ParseAddr(rawIP)
	if err != nil {
		return ""
	}
	if addr.Is4() {
		prefix, err := addr.Prefix(24)
		if err != nil {
			return ""
		}
		return prefix.Masked().String()
	}

	prefix, err := addr.Prefix(64)
	if err != nil {
		return ""
	}
	return prefix.Masked().String()
}

func normalizeHeader(value string, maxLength int) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if maxLength > 0 && len(value) > maxLength {
		return value[:maxLength]
	}

	return value
}
