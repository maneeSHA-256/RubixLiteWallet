# RubixLiteWallet
This is a non-custodial wallet server, which manages keys for rubix nodes. It uses BIP39 to generate keys and to sign. The keys are generated on the curve secp256k1. 

## Commands
### Start server 
```
go run wallet.go

```
### Curl request to create a wallet
```
curl -X POST http://localhost:8081/create_wallet -d '{"port":<rubix node port number in int>}'
```
#### sample with valid request 
```
curl -X POST http://localhost:8081/create_wallet -d '{"port":20009}'
```
**Response:**
```
{"did":"bafybmie5l4jpfxmnnqi3sk4vnt6fx3sbuzf632ubeflc7let6rljzq4usi"}
```
#### sample with invalid request (invalid port)
```
curl -X POST http://localhost:8081/create_wallet -d '{"port":20001}'
```
**Response:**
```
{"error":"Failed to request DID"}
```


### Curl request to generate test RBT
```
curl -X GET "http://localhost:8081//testrbt/create -d '{"did":"<rubix node DID>", "number_of_tokens":<amount in int>}'

```
#### sample with valid request 
```
curl -X POST http://localhost:8081/testrbt/create -d '{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq", "number_of_tokens":1}'
```
**Response:**
```
"Test tokens generated successfully"
```
#### sample with invalid request (invalid input format to number_of_tokens)
```
curl -X POST http://localhost:8081/testrbt/create -d '{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq", "number_of_tokens":1.0}'
```
**Response:**
```
{"error":"Invalid input"}
```


### Curl request to get balance
```
curl -X GET "http://localhost:8081/request_balance?did=<user DID>"

```
#### sample with valid request 
```
curl -X GET "http://localhost:8081/request_balance?did=bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq"
```
**Response:**
```
{"account_info":[{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","did_type":0,"locked_rbt":0,"pinned_rbt":0,"pledged_rbt":0,"rbt_amount":9.6}],"message":"Got account info successfully","result":null,"status":true}
```
#### sample with invalid request (empty input to did)
```
curl -X GET "http://localhost:8081/request_balance?did="
```
**Response:**
```
{"error":"Missing required parameters: port or did"}
```


### Curl request to sign
```
curl -X POST http://localhost:8081/sign -d '{"did":"<rubix node DID>","data":"<signing data>"}'
```
#### sample with valid request 
```
curl -X POST http://localhost:8081/sign -d '{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","data":"txn_data"}'
```
**Response:**
```
{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","signature":"3046022100b28b4bc6de55f419f9e2f887198cb6fd5d50fd59bb90a19fb40b5865ee542b71022100a09201751c45517d1063d2616ef29ec27b94f548c384aa2cb7850de76c69f55c","signedData":"txn_data"}
```
#### sample with invalid request (invalid did)
```
curl -X POST http://localhost:8081/sign -d '{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk287h","data":"txn_data"}'
```
**Response:**
```
{"error":"User not found"}
```


### Curl request to transfer RBTs
```
curl -X POST http://localhost:8081/request_txn -d '{"did":"<sender DID>","receiver":"<receiver DID>", "rbt_amount":<transaction amount in float>}'
```
#### sample with valid request 
```
curl -X POST http://localhost:8081/request_txn -d '{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","receiver":"bafybmiao2fylzuppsr7b7cepm32egd465uhpo3kkwbhnekve6u2bedwb3m", "rbt_amount":1.0}'
```
**Response:**
```
{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkaWQiOiJiYWZ5Ym1pYzZvbGtzdnh1Y3FyeGZid3FwdHlzaHU1dGFocHJhd2huaXBlbWloajdvcGZjY3BrMmRicSIsImV4cCI6MTczMzkwOTUwMCwiaWF0IjoxNzMzODIzMTAwLCJyYnRfYW1vdW50IjoxLCJyZWNlaXZlcl9kaWQiOiJiYWZ5Ym1pYW8yZnlsenVwcHNyN2I3Y2VwbTMyZWdkNDY1dWhwbzNra3diaG5la3ZlNnUyYmVkd2IzbSJ9.srczpeBhwPK9CNa8jy6fLiUtbD0w8gFgBzlkmNRCL0M","status":"Transfer finished successfully in 2.406044531s with trnxid 828face14520df1a64d0760051afa32d8ef0036a95c00d7c9e0501f3ed9b6285"}
```
#### sample with invalid request (invalid rbt_amount)
```
curl -X POST http://localhost:8081/request_txn -d '{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","receiver":"bafybmiao2fylzuppsr7b7cepm32egd465uhpo3kkwbhnekve6u2bedwb3m", "rbt_amount":1.07655}'
```
**Response:**
```
{"did":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkaWQiOiJiYWZ5Ym1pYzZvbGtzdnh1Y3FyeGZid3FwdHlzaHU1dGFocHJhd2huaXBlbWloajdvcGZjY3BrMmRicSIsImV4cCI6MTczMzkwOTU4OSwiaWF0IjoxNzMzODIzMTg5LCJyYnRfYW1vdW50IjoxLjA3NjU1LCJyZWNlaXZlcl9kaWQiOiJiYWZ5Ym1pYW8yZnlsenVwcHNyN2I3Y2VwbTMyZWdkNDY1dWhwbzNra3diaG5la3ZlNnUyYmVkd2IzbSJ9.Cqw_2pR2s27YeG1VVn0L4Oh8Hc4IsWsCOoNA8R4c4aE","status":"transaction amount exceeds 3 decimal places"}
```


### Curl request to get all transactions by DID
```
curl -X GET "http://localhost:8081/txn/by_did?did=<user DID>&role=<Sender/Receiver>&StartDate=<start of the date range>&EndDate=<end of the date range>"

```
**Note** : either provide role of the did or else date range to filter the Txns list

#### sample with valid request 
```
curl -X GET "http://localhost:8081/txn/by_did?did=bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq&role=sender"
```
**Response:**
```
{"TxnDetails":[{"Amount":1,"BlockID":"1-bf67e28f41df5d8bc06e7753a498adef98e79aafae9b23cde6f80960bc39d84c","Comment":"","DateTime":"2024-12-10T11:00:36.290045784+05:30","DeployerDID":"","Epoch":1733808632,"Mode":0,"ReceiverDID":"bafybmiao2fylzuppsr7b7cepm32egd465uhpo3kkwbhnekve6u2bedwb3m","SenderDID":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","Status":true,"TotalTime":3507,"TransactionID":"2df77ca20e0fc5ebf9cd6dea1e18679113a67a5874805d6a89ac239c004157ad","TransactionType":"02"},{"Amount":1.4,"BlockID":"1-f6856fafc6b1ed156cc0006470f5d54614f8cc547b1606f4a3a90bc9132976fd","Comment":"","DateTime":"2024-12-10T11:02:57.115731527+05:30","DeployerDID":"","Epoch":1733808774,"Mode":0,"ReceiverDID":"bafybmiao2fylzuppsr7b7cepm32egd465uhpo3kkwbhnekve6u2bedwb3m","SenderDID":"bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dbq","Status":true,"TotalTime":2805,"TransactionID":"7d8f02a3aff5b9c411bbf3a696ff3067581797f1d43a66a09d0c684760ace7fe","TransactionType":"02"}],"message":"Retrieved Txn Details","result":"Successful","status":true}
```
#### sample with invalid request (invalid did)
```
curl -X GET "http://localhost:8081/txn/by_did?did=bafybmic6olksvxucqrxfbwqptyshu5tahprawhnipemihj7opfccpk2dft&role=sender"
```
**Response:**
```
{"error":"User not found"}
```

