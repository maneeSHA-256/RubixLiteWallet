package main

import (
	"database/sql"
	"strconv"

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
	"github.com/gin-gonic/gin"
	"github.com/tyler-smith/go-bip39"

	_ "github.com/mattn/go-sqlite3"
)

// did request
type DIDRequest struct {
	Port int `json:"port"`
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

// request to rubix node
type ReqToRubixNode struct {
	RubixNodePort string `json:"port"`
	DID           string `json:"did"`
}

// generate test RBT request
type GenerateTestRBTRequest struct {
	// RubixNodePort string `json:"port"`
	DID        string `json:"did"`
	TokenCount int    `json:"number_of_tokens"`
}

// sqlite database: manages tables for user data and jwt tokens
var db *sql.DB

// CORS middleware to enable CORS headers for all incoming requests
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight requests
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	}
}

// Main function to start wallet and node services
func main() {
	// Initialize the database
	var err error
	db, err = storage.InitDatabase()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize JWT with database and secret
	jwt.InitJWT(db, []byte("RubixBIPWallet"))

	// Set up Gin router
	router := gin.Default()

	// Enable CORS middleware
	router.Use(corsMiddleware())

	// API endpoints
	//DID features
	router.POST("/create_wallet", createWalletHandler)
	router.POST("/register_did", registerDIDHandler)
	//RBT features
	router.GET("/request_balance", requestBalanceHandler)
	router.POST("/testrbt/create", createTestRBTHandler)
	//Txn features
	router.POST("/request_txn", requestTransactionHandler)
	router.GET("/txn/by_did", getTxnByDIDHandler)
	router.POST("/sign", signTransactionHandler)

	// Start the Gin server
	log.Println("Starting BIP39 Wallet Services on port 8081...")
	if err := router.Run(":8081"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// Handler: Create a new wallet and request DID from node
func createWalletHandler(c *gin.Context) {
	var req DIDRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Generate mnemonic and derive key pair
	entropy, _ := bip39.NewEntropy(128)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	privateKey, publicKey := generateKeyPair(mnemonic)

	// Request user DID from Rubix node
	did, pubKeyStr, err := didRequest(publicKey, strconv.Itoa(req.Port))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to request DID"})
		return
	}

	// Verify the returned public key
	pubKeyBytes, _ := hex.DecodeString(pubKeyStr)
	reconstructedPubKey, _ := secp256k1.ParsePubKey(pubKeyBytes)
	if !publicKey.IsEqual(reconstructedPubKey) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Public key mismatch \n"})
		return
	}

	// Save user to database
	privKeyStr := hex.EncodeToString(privateKey.Serialize())
	err = storage.InsertUser(did, pubKeyStr, privKeyStr, mnemonic, req.Port)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store user data" + err.Error()})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	// Respond with DID
	c.JSON(http.StatusOK, gin.H{"did": did})
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// Handler: registerDIDHandler publishes the user's DID in the network
func registerDIDHandler(c *gin.Context) {
	var req ReqToRubixNode
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	user, err := storage.GetUserByDID(req.DID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := registerDIDRequest(req.DID, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))

}

// Handler: Sign transaction
func signTransactionHandler(c *gin.Context) {
	var req SignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	user, err := storage.GetUserByDID(req.DID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	dataToSign, _ := hex.DecodeString(req.Data)
	signature, err := signData(user.PrivateKey.ToECDSA(), dataToSign)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign data"})
		return
	}

	// Verify signature
	if !verifySignature(user.PublicKey, dataToSign, signature) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Signature verification failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"did":        user.DID,
		"signature":  hex.EncodeToString(signature),
		"signedData": req.Data,
	})
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// Handler: Request transaction
func requestTransactionHandler(c *gin.Context) {
	var req TxnRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	jwtToken, err := jwt.GenerateJWT(req.DID, req.ReceiverDID, req.RBTAmount)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT"})
		return
	}

	user, err := storage.GetUserByDID(req.DID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	isValid, claims, err := jwt.VerifyToken(jwtToken, user.PublicKey.ToECDSA())
	if !isValid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err})
		return
	}

	log.Println("Token claims:", claims)
	result := SendAuthRequest(jwtToken, strconv.Itoa(user.Port))

	c.JSON(http.StatusOK, gin.H{
		"did":    req.DID,
		"jwt":    jwtToken,
		"status": result,
	})
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// Handler: Request RBT balance
func requestBalanceHandler(c *gin.Context) {
	did := c.Query("did")

	if did == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameter: did"})
		return
	}

	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	result, err := RequestBalance(did, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	c.JSON(http.StatusOK, result)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// Handler: Request to generate test RBTs
func createTestRBTHandler(c *gin.Context) {
	var req GenerateTestRBTRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	user, err := storage.GetUserByDID(req.DID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	resp, err := GenerateTestRBT(req, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
	}

	c.JSON(http.StatusOK, resp)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
}

// Handler: Request to fetch Txns list by DID
func getTxnByDIDHandler(c *gin.Context) {
	did := c.Query("did")

	if did == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required parameter: did \n"})
		return
	}

	role := c.Query("role")
	startDate := c.Query("StartDate")
	endDate := c.Query("EndDate")

	user, err := storage.GetUserByDID(did)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	result, err := RequestTxnsByDID(did, role, startDate, endDate, strconv.Itoa(user.Port))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err})
		// Add a newline to the response body if required
		c.Writer.Write([]byte("\n"))
		return
	}

	c.JSON(http.StatusOK, result)
	// Add a newline to the response body if required
	c.Writer.Write([]byte("\n"))
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
func SendAuthRequest(jwtToken string, rubixNodePort string) string {
	log.Println("sending auth request to rubix node...")
	authURL := fmt.Sprintf("http://localhost:%s/api/send-jwt-from-wallet", rubixNodePort)
	req, err := http.NewRequest("POST", authURL, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
		return "Failed to create request"
	}

	// Add headers
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Content-Type", "application/json")

	// Make the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error sending request: %v", err)
		return "Error sending request"
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response: %v", err)
		return "Error reading response"
	}

	fmt.Printf("Response from Rubix Node: %s\n", body)
	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
		return "Error unmarshaling response"
	}

	result := response["message"].(string)
	return result
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

// RequestBalance sends request to Rubix node to provide RBT balance info
func RequestBalance(did string, rubixNodePort string) (map[string]interface{}, error) {

	url := fmt.Sprintf("http://localhost:%s/api/get-account-info?did=%s", rubixNodePort, did)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Parse the response into a map
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}
	return response, nil
}

// GenerateTestRBT sends request to generate test RBTs for userd
func GenerateTestRBT(data GenerateTestRBTRequest, rubixNodePort string) (string, error) {

	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/generate-test-token", rubixNodePort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return "", err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return "", err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return "", err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return "", fmt.Errorf("test token generation failed, %s", respMsg)
	}

	return respMsg, nil
}

// RequestTxnsByDID sends request to Rubix node to provide list of all Txns involving the DID
func RequestTxnsByDID(did string, role string, startDate string, endDate string, rubixNodePort string) (map[string]interface{}, error) {

	url := fmt.Sprintf("http://localhost:%s/api/get-by-did?DID=%s&Role=%s&StartDate=%s&EndDate=%s", rubixNodePort, did, role, "", "")
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return nil, err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return nil, err
	}

	// Parse the response into a map
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}
	return response, nil
}

// registerDIDRequestsends request to rubix node to publish the did info in the network
func registerDIDRequest(did string, rubixNodePort string) (string, error) {
	data := map[string]interface{}{
		"did": did,
	}
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/register-did", rubixNodePort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyJSON))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return "", err
	}

	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return "", err
	}
	defer resp.Body.Close()
	data2, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %s\n", err)
		return "", err
	}

	// Process the data as needed
	var response map[string]interface{}
	err = json.Unmarshal(data2, &response)
	if err != nil {
		fmt.Println("Error unmarshaling response:", err)
	}

	respMsg := response["message"].(string)
	respStatus := response["status"].(bool)

	if !respStatus {
		return "", fmt.Errorf("test token generation failed, %s", respMsg)
	}

	return respMsg, nil
}
