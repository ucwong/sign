package util

import (
	"fmt"
	"log"

	"github.com/CortexFoundation/CortexTheseus/common"
	"github.com/CortexFoundation/CortexTheseus/common/hexutil"
	"github.com/CortexFoundation/CortexTheseus/crypto"
)

const (
	testpri = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"
)

func Verify(msg, addr, sig string) bool {
	/*if len(msg) == 0 || len(addr) == 0 || len(sig) == 0 || timestamp == 0 {
		log.Println("params failed msg:" + msg + ", addr:" + addr + ", sig:" + sig)
		return false
	}

	if time.Now().Unix()-int64(30) > timestamp {
		return false
	}

	if time.Now().Unix()+int64(30) < timestamp {
		return false
	}*/

	//sig_, _ := SignData(msg, testpri)
	//log.Printf("[signature] : want:%s, have:%s", hexutil.Encode(sig_[:]), sig)
	s := hexutil.MustDecode(sig)

	if len(s) == 0 {
		log.Println("Signature failed m")
		return false
	}
	recoveredAddr, err := EcRecover([]byte(msg), s)
	if err != nil {
		log.Println(err)
		return false
	}

	if common.HexToAddress(addr) != recoveredAddr {
		log.Printf("Address mismatch: want: %v have: %v\n", addr, recoveredAddr.Hex())
		return false
	}

	return true
}

func EcRecover(data, sig hexutil.Bytes) (common.Address, error) {
	if len(sig) != 65 {
		return common.Address{}, fmt.Errorf("signature must be 65 bytes long")
	}
	if sig[64] != 27 && sig[64] != 28 {
		return common.Address{}, fmt.Errorf("invalid Cortex signature (V is not 27 or 28) %v", sig[64])
	}
	sig[64] -= 27 // Transform yellow paper V from 27/28 to 0/1
	hash, _ := SignHash(data)
	rpk, err := crypto.SigToPub(hash, sig)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*rpk), nil
}

func SignHash(data []byte) ([]byte, string) {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg)), msg
}

func SignData(msg string, pri string) (sig []byte, err error) {
	k0, _ := crypto.HexToECDSA(pri)
	msg0, _ := SignHash([]byte(msg)) //Keccak256([]byte(msg))
	sig, err = crypto.Sign(msg0, k0)
	sig[64] += 27
	return
}
