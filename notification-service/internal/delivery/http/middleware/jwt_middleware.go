package middleware

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"golang-clean-architecture/internal/shared/response"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type Claims struct {
	Roles                []string `json:"roles"`
	UserCode             string   `json:"userCode"`
	Type                 string   `json:"type"`
	jwt.RegisteredClaims          // Subject (sub) = userId
}

var publicKey *rsa.PublicKey

func LoadPublicKey(v *viper.Viper, log *logrus.Logger) error {
	keyPath := v.GetString("jwt.public_key_path")
	if keyPath == "" {
		return fmt.Errorf("jwt public key path is not defined in config")
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		log.Errorf("Failed to read public key file at %s: %v", keyPath, err)
		return err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			log.Errorf("Gagal total parsing public key: %v", err)
			return err
		}
	}

	var ok bool
	publicKey, ok = pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}

	log.Infof("JWT Public Key loaded successfully from %s", keyPath)
	return nil
}

func JWTProtected(log *logrus.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		correlationID, ok := c.Locals("correlationId").(string)
		if !ok {
			correlationID = ""
		}

		authHeader := c.Get("Authorization")
		if authHeader == "" {
			if token := c.Query("token"); token != "" {
				authHeader = "Bearer " + token
			}
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			log.WithFields(logrus.Fields{
				"correlation_id": correlationID,
				"ip":             c.IP(),
			}).Warn("Missing or invalid Authorization header prefix")

			return c.Status(fiber.StatusUnauthorized).JSON(
				response.Error("Missing or invalid Authorization header", correlationID),
			)
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return publicKey, nil
		})

		if err != nil || !token.Valid {
			log.WithFields(logrus.Fields{
				"correlation_id": correlationID,
				"error":          err.Error(),
			}).Warn("JWT Token validation failed")

			return c.Status(fiber.StatusUnauthorized).JSON(
				response.Error("Invalid or expired token", correlationID),
			)
		}

		claims, ok := token.Claims.(*Claims)
		if !ok {
			log.WithFields(logrus.Fields{
				"correlation_id": correlationID,
			}).Error("Failed to cast JWT claims")

			return c.Status(fiber.StatusUnauthorized).JSON(
				response.Error("Invalid token claims", correlationID),
			)
		}

		// userId dari sub
		uid, err := uuid.Parse(claims.Subject)
		if err != nil {
			log.WithFields(logrus.Fields{
				"correlation_id": correlationID,
			}).Error("Failed to parse userId from sub claim")

			return c.Status(fiber.StatusUnauthorized).JSON(
				response.Error("Invalid user ID in token claims", correlationID),
			)
		}

		// role ambil index 0
		role := ""
		if len(claims.Roles) > 0 {
			role = claims.Roles[0]
		}

		// log pakai userCode — non-sensitive
		log.WithFields(logrus.Fields{
			"correlation_id": correlationID,
			"user_code":      claims.UserCode,
		}).Debug("JWT Authentication successful")

		c.Locals("userId", uid)
		c.Locals("userCode", claims.UserCode)
		c.Locals("role", role)

		return c.Next()
	}
}
