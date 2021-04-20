package main

import (
	"github.com/CortexFoundation/CortexTheseus/common/hexutil"
	"github.com/ucwong/sign/util"
	"log"
	"time"
)

const (
	testpri = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"
)

func main() {
	msg := "hello"
	sig, err := util.SignData(msg, testpri)
	if err != nil {
		log.Println(err)
	}
	suc := util.Verify(msg, "0x970E8128AB834E8EAC17Ab8E3812F010678CF791", hexutil.Encode(sig[:]), time.Now().Unix())
	if suc {
		log.Println("Sign suc")
	}
}
