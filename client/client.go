// Implementation of a TCP client that sends a random string to
//a  server listening and check the signature against the server
// public key
package main

import "fmt"
import "net"
import "math/rand"
import "bufio"
import "bytes"
import "crypto/cipher"
import "github.com/dedis/crypto/abstract"
import "github.com/dedis/crypto/nist"
import "errors"

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
	// And check that hashElgamal for T and the message == c
	buf := bytes.Buffer{}
	sig := basicSig{c, r}
	abstract.Write(&buf, &sig, suite)
	return buf.Bytes()
}


// Return a random seequence.
func randSeq(n int) string {
    b := make([]rune, n)
    var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    for i := range b {
        b[i] = letters[rand.Intn(len(letters))]
    }
    return string(b)
}

// Verify the signature.
func SchnorrVerify(suite abstract.Suite, message []byte, publicKey abstract.Point,
	signatureBuffer []byte) error {

	// Decode the signature
	buf := bytes.NewBuffer(signatureBuffer)
	sig := basicSig{}
	if err := abstract.Read(buf, &sig, suite); err != nil {
		return err
	}
	r := sig.R
	c := sig.C

	// Compute base**(r + x*c) == T
	var P, T abstract.Point
	P = suite.Point()
	T = suite.Point()
	T.Add(T.Mul(nil, r), P.Mul(publicKey, c))

	// Verify that the hash based on the message and T
	// matches the challange c from the signature.
	c = hashSchnorr(suite, message, T)
	if !c.Equal(sig.C) {
		return errors.New("invalid signature")
	}

	return nil
}

// TCP client that connects to a localhost server
// on port 8080 and send a random stream of 1024 elments.
func main() {

	fmt.Println("client")
	conn, err := net.Dial("tcp", "localhost:9000")
	if err != nil {
		panic(err.Error())
	}

	// Create a public/private keypair (X,x)
	suite := nist.NewAES128SHA256P256()
	rand := suite.Cipher([]byte("static"))		//initialize with "static"
	x := suite.Secret().Pick(rand) 				// create a private key x
	X := suite.Point().Mul(nil, x) 				// corresponding public key X

	fmt.Println("The public key is :" , X)	

	//generate a random message and send it to the server
	message := randSeq(1024) + "\n"
	fmt.Fprintf(conn, message)

	//read signature from server
	response, _ := bufio.NewReader(conn).ReadString('\t')
	response = response[:(len(response) - 1)]  //trimming the tabulation
	fmt.Println("Received signature from server ")

	M := []byte(message[:(len(message) - 1)]) 			

	// Verify the signature against the correct message
	err = SchnorrVerify(suite, M , X, []byte(response))
	if err != nil {
		panic(err.Error())
	}
	fmt.Println("Signature verified against correct message.")

	conn.Close()
}








