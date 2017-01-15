/*
Gencrypt is a Go package that acts as a wrapper around portions of the
standard libraries crypto package.

/////////////////////////////////////
// Example Usage: ///////////////////
/////////////////////////////////////

package main

import (
  "fmt"

  "gitlab.com/zfeldt/gencrypt"
)

// NOTE: Error checking not handled in this example but should be in
// production.

var (
  // Data you want to encrypt
  data = []byte("test data")
  // Secret key
  key = []byte("12345678901234561234567890123456")
)

func main() {
  // Get the GCM
  gcm, _ := gencrypt.NewGCM(key)

  // Encrypt data
  enc, _ := gcm.AESEncrypt(data)

  // Decrypt data
  dec, _ := gcm.AESDecrypt(enc)
  fmt.Println(string(dec))
}
*/
package gencrypt
