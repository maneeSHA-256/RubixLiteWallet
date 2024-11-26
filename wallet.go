package main

import (
	"database/sql"

	jwt "github.com/maneeSHA-256/RubixLiteWallet/jwt"
	storage "github.com/maneeSHA-256/RubixLiteWallet/storage"

	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/tyler-smith/go-bip39"

	_ "github.com/mattn/go-sqlite3"
)

// did request
type DIDRequest struct {
	Port string `json:"port"`
}

// sign request
type SignRequest struct {
	Data string `json:"data"`
	DID  string `json:"did"`
}

// sign response
type SignResponse struct {
	DID        string `json:"did"`
	Signature  string `json:"signature"`
	SignedData string `json:"signed_data"`
}

// transaction request
type TxnRequest struct {
	RubixNodePort string  `json:"port"`
	DID           string  `json:"did"`
	ReceiverDID   string  `json:"receiver"`
	RBTAmount     float64 `json:"rbt_amount"`
}

// sqlite database: manages tables for user data and jwt tokens
var db *sql.DB

// Main function to start wallet and node services
func main() {
	// Initialize storage module and get the db object
	var err error
	db, err = storage.InitDatabase()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	jwt.InitJWT(db, []byte("RubixBIPWallet"))

	// Register HTTP handlers
	http.HandleFunc("/create_wallet", createWalletHandler)
	http.HandleFunc("/sign", signTransactionHandler)
	http.HandleFunc("/request_txn", requestTransactionHandler)

	fmt.Println("Starting BIP39 Wallet Services...")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

// Handler: Create a new wallet with BIP39 keys and request user ID from node
func createWalletHandler(w http.ResponseWriter, r *http.Request) {
	var req DIDRequest
	json.NewDecoder(r.Body).Decode(&req)

	// Generate mnemonic
	entropy, _ := bip39.NewEntropy(128)
	mnemonic, _ := bip39.NewMnemonic(entropy)

	// Derive key pair
	pvtKey, publicKey := generateKeyPair(mnemonic)

	// Request user ID (IPFS hash) from node
	did, pubKeystr, err := didRequest(publicKey, req.Port)
	if err != nil {
		log.Fatal("failed did request from rubix node, err:", err)
	}

	// Convert hex string back to bytes
	pubKeyByte, err := hex.DecodeString(pubKeystr)
	if err != nil {
		log.Fatalf("Failed to decode hex string: %v", err)
	}
	reconstructedPubKey, err := secp256k1.ParsePubKey(pubKeyByte)
	if err != nil {
		log.Fatal("failed to parse public key, err:", err)
	}
	// Check if the reconstructed key matches the original
	if publicKey.IsEqual(reconstructedPubKey) {
		log.Println("Response public key matches the original!")
	} else {
		log.Println("Response public key does NOT match the original.")
		return
	}

	// Convert keys to strings
	privKeyStr := hex.EncodeToString(pvtKey.Serialize())
	pubKeyStr := hex.EncodeToString(publicKey.SerializeCompressed())

	// Store user data in the database
	err = storage.InsertUser(did, pubKeyStr, privKeyStr, mnemonic)
	if err != nil {
		log.Fatalf("failed to store user data in database: %v", err)
	}

	resp := map[string]string{"did": did}
	json.NewEncoder(w).Encode(resp)
}

// Handler: Sign transaction data with user's private key and respond with signature
func signTransactionHandler(w http.ResponseWriter, r *http.Request) {
	var req SignRequest
	json.NewDecoder(r.Body).Decode(&req)

	user, err := storage.GetUserByDID(req.DID)
	if err != nil {
		log.Fatalf("failed to get user data: %v", err)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	fmt.Println("sign request:", req)

	// Signing data
	dataToSign := make([]byte, hex.DecodedLen(len(req.Data)))
	hex.Decode(dataToSign, []byte(req.Data))

	signature, err := signData(user.PrivateKey.ToECDSA(), dataToSign)
	if err != nil {
		log.Fatal("\n failed to sign in wallet, err:", err)
	}

	sigStr := hex.EncodeToString(signature)

	fmt.Printf("signature data: \n sig: %v \n data: %v \n pubKey: %v", sigStr, dataToSign, *user.PublicKey.ToECDSA())
	isValid := verifySignature(user.PublicKey, dataToSign, signature)
	if !isValid {
		log.Fatal("\n signature verification failed")
	} else {
		log.Println("signature verified successfully")
	}

	// Respond with signature and signed data
	resp := SignResponse{
		DID:        user.DID,
		Signature:  sigStr,
		SignedData: req.Data,
	}
	json.NewEncoder(w).Encode(resp)
}

func requestTransactionHandler(w http.ResponseWriter, r *http.Request) {
	var req TxnRequest
	json.NewDecoder(r.Body).Decode(&req)

	jwtToken, err := jwt.GenerateJWT(req.DID, req.ReceiverDID, req.RBTAmount)
	if err != nil {
		log.Fatal("failed to generate jwt, err:", err)
		http.Error(w, "Failed to generate JWT", http.StatusInternalServerError)
	}

	//fetch user public key
	user, err := storage.GetUserByDID(req.DID)
	if err != nil {
		log.Fatalf("failed to get user data: %v", err)
	}

	//verifying jwt token
	isValidTkn, tknClaims, err := jwt.VerifyToken(jwtToken, user.PublicKey.ToECDSA())
	if isValidTkn {
		log.Println("valid token with claims:", tknClaims)
	} else {
		log.Fatal("err:", err)
	}
	// SendAuthRequest(jwtToken, req.RubixNodePort)
	// Respond with the JWT
	resp := map[string]string{
		"did":    req.DID,
		"jwt":    jwtToken,
		"status": "Transaction JWT generated successfully",
	}
	json.NewEncoder(w).Encode(resp)
}

// Generate secp256k1 key pair from mnemonic
func generateKeyPair(mnemonic string) (*secp256k1.PrivateKey, *secp256k1.PublicKey) {
	seed := bip39.NewSeed(mnemonic, "")
	privateKey := secp256k1.PrivKeyFromBytes(seed[:32])
	publicKey := privateKey.PubKey()
	return privateKey, publicKey
}

// send DID request to rubix node
func didRequest(pubkey *secp256k1.PublicKey, rubixNodePort string) (string, string, error) {
	pubKeyStr := hex.EncodeToString(pubkey.SerializeCompressed())
	data := map[string]interface{}{
		"public_key": pubKeyStr,
	}
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/request-did-for-pubkey", rubixNodePort)
	req, err := http.NewRequest("GET", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return "", "", err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return "", "", err
	}
	defer resp.Body.Close()
	fmt.Println("Response Status:", resp.Status)
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return "", "", err
	}

	fmt.Println("Response Body in did request :", string(data2))

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respPubKey := response["public_key"].(string)
	respDID := response["did"].(string)

	return respDID, respPubKey, nil
}

// SendAuthRequest sends a JWT authentication request to the Rubix node
func SendAuthRequest(jwtToken string, rubixNodePort string) {
	authURL := fmt.Sprintf("http://localhost:%s/api/jwt-authenticate", rubixNodePort)
	req, err := http.NewRequest("POST", authURL, bytes.NewBuffer([]byte(jwtToken)))
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	// Add headers
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json")

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error sending request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response: %v", err)
	}

	fmt.Printf("Response from Rubix Node: %s\n", body)
}

// Sign data using secp256k1 private key
func signData(privateKey crypto.PrivateKey, data []byte) ([]byte, error) {
	//use sign function from crypto library
	signature, err := privateKey.(crypto.Signer).Sign(rand.Reader, data, crypto.SHA3_256)
	if err != nil {
		log.Fatalf("Failed to sign data: %v", err)
		return nil, err
	}

	// return signature, signedData
	return signature, nil
}

// verifySignature verifies the signature using the public key.
func verifySignature(publicKey *secp256k1.PublicKey, data []byte, signature []byte) bool {
	pubKey := publicKey.ToECDSA()

	// Verify the signature using ECDSA's VerifyASN1 function.
	isValid := ecdsa.VerifyASN1(pubKey, data, signature)

	return isValid
}
