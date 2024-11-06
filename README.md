# RubixLiteWallet
This is a non-custodial wallet server, which manages keys for rubix nodes. It uses BIP39 to generate keys and to sign. The keys are generated on the curve secp256k1. 

## Commands
### Start server 
go run wallet.go

### Curl request to create a wallet
curl -X POST http://localhost:8080/create_wallet -d '{"port":"<rubix node port number>"}'

### Curl request to sign
curl -X GET http://localhost:8080/sign -d '{"did":"<rubix node DID>","data":"txn_data"}'