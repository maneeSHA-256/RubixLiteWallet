package main

import (
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
	"os"

	// "github.com/btcsuite/btcd/btcec/v2"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/tyler-smith/go-bip39"
	// crypto "github.com/rubixchain/rubixgoplatform/crypto"
	// "github.com/rubixchain/rubixgoplatform/util"
	// "github.com/rubixchain/rubixgoplatform/wrapper/uuid"
)

const (
	// PvtKeyFileName   string = "pvtKey.txt"
	PubKeyFileName   string = "pubKey.txt"
	MnemonicFileName string = "mnemonic.txt"
	// pwd              string = "mypassword"
	// childPath        int    = 0
	dir string = "./Rubix/"
)

// User data structure for wallet management
type User struct {
	DID       string // IPFS hash (simulated)
	PublicKey *secp256k1.PublicKey
	// ChildPath int
	Mnemonic string
}

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

// Wallet service: holds user key pairs in memory for simplicity
var wallet = make(map[string]*User)

// Main function to start wallet and node services
func main() {
	http.HandleFunc("/create_wallet", createWalletHandler)
	http.HandleFunc("/sign", signTransactionHandler)

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
	_, publicKey := generateKeyPair(mnemonic)

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
		fmt.Println("Response public key matches the original!")
	} else {
		fmt.Println("Response public key does NOT match the original.")
	}
	// Store user data
	user := &User{PublicKey: publicKey, DID: did, Mnemonic: mnemonic}
	wallet[did] = user

	saveUserData(user)

	// // Respond with wallet details
	resp := map[string]string{"did": did}
	json.NewEncoder(w).Encode(resp)
}

// Handler: Sign transaction data with user's private key and respond with signature
func signTransactionHandler(w http.ResponseWriter, r *http.Request) {
	var req SignRequest
	json.NewDecoder(r.Body).Decode(&req)

	userDir := dir + req.DID
	_, err := os.Stat(userDir)
	if os.IsNotExist(err) {
		log.Fatal("invalid did, did folder does not exist")
		return // Folder doesn't exist
	}

	//read mnemonic
	mnemonic, err := os.ReadFile(userDir + "/private/" + MnemonicFileName)
	if err != nil {
		log.Fatal("err:", err)
		return
	}

	// derive privatekey from mnemonic
	privKey, err := derivePrivateKey(string(mnemonic))
	if err != nil {
		log.Fatal("err:", err)
		return
	}

	//read public key
	pubKeyBytes, err := os.ReadFile(userDir + "/public/" + PubKeyFileName)
	if err != nil {
		log.Fatal("err:", err)
		return
	}

	pubKey, err := secp256k1.ParsePubKey(pubKeyBytes)
	if err != nil {
		log.Fatal("failed to parse public key bytes, err", err)
	}

	user := User{
		DID:       req.DID,
		PublicKey: pubKey,
	}
	fmt.Println("sign request:", req)

	// Sign the data
	dst := make([]byte, hex.DecodedLen(len(req.Data)))
	hex.Decode(dst, []byte(req.Data))

	signature, err := signData(privKey.ToECDSA(), dst)
	if err != nil {
		log.Fatal("failed to sign in wallet, err:", err)
		return
	}

	sigstr := hex.EncodeToString(signature)
	sigbyt, _ := hex.DecodeString(sigstr)

	fmt.Printf("signature data: \n sig: %v \n data: %v \n pubKey: %v", sigstr, dst, *user.PublicKey.ToECDSA())
	isValid := verifySignature(user.PublicKey, dst, sigbyt)
	if !isValid {
		log.Fatal("signature verification failed")
		return
	}

	// Respond with signature and signed data
	resp := SignResponse{
		DID:        user.DID,
		Signature:  sigstr,
		SignedData: req.Data,
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

// DerivePrivateKey generates the private key from the mnemonic when needed
func derivePrivateKey(mnemonic string) (*secp256k1.PrivateKey, error) {
	// Derive the seed and private key from the mnemonic here
	seed := bip39.NewSeed(mnemonic, "")
	privateKey := secp256k1.PrivKeyFromBytes(seed[:32])

	return privateKey, nil
}

// send DID request to rubix node
func didRequest(pubkey *secp256k1.PublicKey, port string) (string, string, error) {
	pubKeyStr := hex.EncodeToString(pubkey.SerializeUncompressed())
	data := map[string]interface{}{
		"public_key": pubKeyStr,
	}
	bodyJSON, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return "", "", err
	}

	url := fmt.Sprintf("http://localhost:%s/api/request-did-for-pubkey", port)
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
		// resp.Body.Close()
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

// save user data into did folder
func saveUserData(user *User) error {
	dirName := dir + user.DID
	err := os.MkdirAll(dirName+"/private", os.ModeDir|os.ModePerm)
	if err != nil {
		log.Fatal("failed to create directory", "err", err)
		return err
	}

	err = os.MkdirAll(dirName+"/public", os.ModeDir|os.ModePerm)
	if err != nil {
		log.Fatal("failed to create directory", "err", err)
		return err
	}

	//write mnemonic key to file
	err = FileWrite(dirName+"/private/"+MnemonicFileName, []byte(user.Mnemonic))
	if err != nil {
		log.Fatal("failed to write mnemonic file", "err", err)
		return err
	}

	//write public key to file
	err = FileWrite(dirName+"/public/"+PubKeyFileName, user.PublicKey.SerializeCompressed())
	if err != nil {
		log.Fatal("failed to write public key file", "err", err)
		return err
	}

	// //write child path to file
	// err = FileWrite(dirName+"/childpath.txt", []byte(strconv.Itoa(user.ChildPath)))
	// if err != nil {
	// 	log.Fatal("failed to write child path file", "err", err)
	// 	return err
	// }

	return nil
}

// write to file
func FileWrite(fileName string, data []byte) error {
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err != nil {
		return err
	}
	f.Close()
	return nil
}
