// Implementation of a TCP server that listen on port 9000
//and receives a text. A signature is generated from the text and
// returned to the client
package main

import "fmt"
import "net"
import "bufio"
import "bytes"
import "crypto/cipher"
import "encoding/hex"
import "github.com/dedis/crypto/abstract"
import "github.com/dedis/crypto/nist"


// A basic, verifiable signature.
type basicSig struct {
	C abstract.Secret // challenge
	R abstract.Secret // response
}

// Returns a secret that depends on on a message and a point.
func hashSchnorr(suite abstract.Suite, message []byte, p abstract.Point) abstract.Secret {
	pb, _ := p.MarshalBinary()
	c := suite.Cipher(pb)
	c.Message(nil, nil, message)
	return suite.Secret().Pick(c)
}

// This simplified implementation of Schnorr Signatures is based on
// crypto/anon/sig.go
// The ring structure is removed and
// The anonimity set is reduced to one public key = no anonimity.
func SchnorrSign(suite abstract.Suite, random cipher.Stream, message []byte,
	privateKey abstract.Secret) []byte {

	// Create random secret v and public point commitment T
	v := suite.Secret().Pick(random)
	T := suite.Point().Mul(nil, v)

	// Create challenge c based on message and T
	c := hashSchnorr(suite, message, T)

	// Compute response r = v - x*c
	r := suite.Secret()
	r.Mul(privateKey, c).Sub(v, r)

	// Return verifiable signature {c, r}
	// Verifier will be able to compute v = r + x*c
	// And check that hashElgamal for T and the message == c.
	buf := bytes.Buffer{}
	sig := basicSig{c, r}
	abstract.Write(&buf, &sig, suite)
	return buf.Bytes()
}

// Handles the request, if the message is 1024 bytes
// then comptues the signature of the message received
// and returns it to the client.
func handleConnection(conn net.Conn, suite abstract.Suite, rand abstract.Cipher, x abstract.Secret) {
	message, _ := bufio.NewReader(conn).ReadString('\n')
	if len(message) == 1025 {
		message = message[:(len(message) - 1)]
		M := []byte(message) 			
		sig := SchnorrSign(suite, rand, M, x)
		fmt.Print("Signature:\n" + hex.Dump(sig))

		conn.Write([]byte(string(sig) + "\t"))
	}
	conn.Close()
}

//Listen on port 9000 and serves client requests
//by returning a signature of the text received.
func main() {

    suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("static"))			//initialize with "static"
	// Create a public/private keypair (X,x)
	x := suite.Secret().Pick(rand) // create a private key x

	ln, err := net.Listen("tcp", ":9000")
	if err != nil {
		// handle error
	}
	defer ln.Close()

	fmt.Println("Server ready on port 9000")

	for {
		conn, _ := ln.Accept()
		go  handleConnection(conn, suite, rand, x)
	}
	


}