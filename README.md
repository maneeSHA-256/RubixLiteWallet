# RubixLiteWallet
This is a non-custodial wallet server, which manages keys for rubix nodes. It uses BIP39 to generate keys and to sign. The keys are generated on the curve secp256k1. 

## Commands
### Start server 
```
go run wallet.go

```
### Curl request to create a wallet
```
curl -X POST http://localhost:8081/create_wallet -d '{"port":"<rubix node port number>"}'
```

### Curl request to generate test RBT
```
curl -X GET "http://localhost:8081//testrbt/create -d '{"did":"<rubix node DID>", "number_of_tokens":<amount in int>}'

```

### Curl request to get balance
```
curl -X GET "http://localhost:8081/request_balance?did=<user DID>"

```

### Curl request to sign
```
curl -X POST http://localhost:8081/sign -d '{"did":"<rubix node DID>","data":"<signing data>"}'
```

### Curl request to request Transaction
```
curl -X POST http://localhost:8081/request_txn -d '{"did":"<sender DID>","receiver":"<receiver DID>", "rbt_amount":<transaction amount in float>}'
```
