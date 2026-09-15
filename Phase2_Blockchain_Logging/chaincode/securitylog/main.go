package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	chaincode, err := contractapi.NewChaincode(&SecurityLogContract{})
	if err != nil {
		log.Panicf("error creating securitylog chaincode: %v", err)
	}
	if err := chaincode.Start(); err != nil {
		log.Panicf("error starting securitylog chaincode: %v", err)
	}
}
