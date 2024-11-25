package jwt

import (
	"database/sql"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
)

var db *sql.DB
var jwtSecret []byte

// Initialize JWT module with database connection and secret
func InitJWT(database *sql.DB, secret []byte) {
	if db == nil {
		log.Println("Database connection in InitJWT is nil")
	} else {
		log.Println("JWT initialized with database connection")
	}

	db = database
	jwtSecret = secret
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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
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
