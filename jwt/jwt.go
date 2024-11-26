package jwt

import (
	"crypto/ecdsa"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/maneeSHA-256/RubixLiteWallet/storage"
)

var db *sql.DB

// Initialize JWT module with database connection and secret
func InitJWT(database *sql.DB, secret []byte) {
	if db == nil {
		log.Println("Database connection in InitJWT is nil")
	} else {
		log.Println("JWT initialized with database connection")
	}

	db = database
}

// generate JWT
func GenerateJWT(did string, receiverDID string, amount float64) (string, error) {
	claims := jwt.MapClaims{
		"did":          did,
		"receiver_did": receiverDID,
		"rbt_amount":   amount,
		"iat":          time.Now().Unix(),
		"exp":          time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	//fetch user's private key to sign
	user, err := storage.GetUserByDID(did)
	if err != nil {
		log.Println("failed to fetch user data to sign the jwt, err:", err)
		return "", err
	}
	// define token header
	token.Header["alg"] = "ES256"
	token.Header["typ"] = "JWT"

	//get the signed token
	tokenString, err := token.SignedString(user.PrivateKey.ToECDSA())
	if err != nil {
		return "", err
	}

	// Save token to database
	_, err = db.Exec(
		"INSERT INTO jwt_tokens (did, token, issued_at, expires_at) VALUES (?, ?, ?, ?)",
		did, tokenString, claims["iat"], claims["exp"],
	)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Verify JWT token using public key
func VerifyToken(tokenString string, publicKey *ecdsa.PublicKey) (bool, jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is ECDSA
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		log.Printf("failed to parse jwt")
		return false, nil, err
	}

	// Extract and validate claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return true, claims, nil
	}

	return false, nil, fmt.Errorf("invalid token")
}
