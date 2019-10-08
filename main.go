package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	lcrypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
)

func main() {
	var (
		f   *os.File
		csv string
		id  peer.ID
		err error
	)

	for i := 0; i < 100; i++ {
		pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}

		priv, _, err := lcrypto.KeyPairFromStdKey(pk)
		if err != nil {
			log.Fatal(err)
		}

		bs, err := x509.MarshalPKCS8PrivateKey(pk)
		if err != nil {
			log.Fatal(err)
		}

		f, err = os.Create(fmt.Sprintf("./pems/pk-%d.pem", i+1))
		if err != nil {
			log.Fatal(err)
		}

		if err := pem.Encode(
			f,
			&pem.Block{
				Type:  "ECDSA PRIVATE KEY",
				Bytes: bs,
			},
		); err != nil {
			log.Fatal(err)
		}

		id, err = peer.IDFromPrivateKey(priv)
		if err != nil {
			log.Fatal(err)
		}

		csv += fmt.Sprintf("pk-%d,%s\n", i+1, id)
	}

	if err = ioutil.WriteFile("./pems/data.csv", []byte(csv), 0644); err != nil {
		log.Fatal(err)
	}

	log.Println("done")
}
