// gencrypt is a package to further ease the use of encryption with the Go
// programming language.
// Copyright (C) 2017 J. Hartzfeldt

// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation; either version 2 of the License, or (at your option)
// any later version.

// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.

// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc., 51
// Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

// Package gencrypt provides methods for encrypting and decrypting data with the
// AES256 encryption method, this is the test file for it.
package gencrypt

import (
	"crypto/aes"
	"strings"
	"testing"

	"gitlab.com/sigma7/slicerip"
	"gitlab.com/zfeldt/gencrypt"
)

// NOTE: Encryption can be tricky and it's important to run a few visual tests
// to visually verify that data being returned is 100% encrypted. Run this test
// with the -v flag (go test -v) to see logging output and to visually compare
// encrypted data with the original.

// Here we define the data we want to encrypt and the key used to encrypt and
// decrypt it.
var (
	// data should be of length aes/cipher.BlockSize + n where n > 0 to ensure
	// that multiple blocks are being encrypted/decrypted.
	data = []byte(`test test test test test test test test test test test test
test test test test test test test test test test test test test test test test
test test test test test test test test test test test test test test test test
test test test test test test test test test test test test test test test test
test test test test test test test test test test test test test test test test
`)
	key = []byte("12345678901234561234567890123456")
)

// Visual inspection test, make sure to use the -v flag (go test -v) for
// logging and to visually inspect the encrypted data to make sure it contains
// no substrings of the original data.
func TestVisual(t *testing.T) {
	gcm, _ := gencrypt.NewGCM(key)
	encData, _ := gcm.AESEncrypt(data)
	t.Log("UNENCRYPTED DATA:")
	t.Log(string(data))
	t.Log("////////////////////////////////////////////////")
	t.Log("////////////////////////////////////////////////")
	t.Log("////////////////////////////////////////////////")
	t.Log("ENCRYPTED DATA:")
	t.Log(string(encData))
	t.Log("////////////////////////////////////////////////")
	t.Log("////////////////////////////////////////////////")
	t.Log("////////////////////////////////////////////////")
}

// Test Encryption and Decryption:
func TestGencrypt(t *testing.T) {
	// Get the Galois Counter Mode
	gcm, err := gencrypt.NewGCM(key)
	handleErr(err, t)

	// Encryption test, using the Galois struct returned above
	encData, err := gcm.AESEncrypt(data)
	handleErr(err, t)

	// We can run all sorts of tests to make sure the data isn't *obviously*
	// unencrypted, but sometimes data can be partially encrypted, for example,
	// if the Galois Counter Mode was implemented incorrectly and portions of
	// blocks were left unencrypted. This type of stuff is taken care of by the
	// core Go developers, but it's up to the user to use the tools provided by
	// the standard library.

	// Test: check to see if the data is exactly the same:
	if string(encData) == string(data) {
		t.Error(`ENCRYPTION FAILED!!!`, string(encData))
	}

	// Test: check to see if a substring exists within the encrypted data that
	// matches a substring of length n in the original data, it's important to
	// choose a reasonable length for n or this test could easily fail because
	// you're bound to randomly generate matching substrings, the smaller the
	// number, the more likely you are to have a false positive, the following
	// line rips strings with a minimum length of 3 and a maximum length of 10:
	ripped := slicerip.Extract(string(data), 3, 10)
	for _, v := range ripped {
		if strings.Contains(string(encData), v) {
			t.Error("TEST FAILED: ENCRYPTED DATA APPEARS TO CONTAIN ORIGINAL DATA.")
		}
	}

	// Decryption test, using the Galois struct returned above
	decData, err := gcm.AESDecrypt(encData)
	handleErr(err, t)

	// Test: Make sure the decrypted data matches the original data:
	if string(decData) != string(data) {
		t.Error("TEST FAILED: DECRYPTED DATA DOES NOT MATCH ORIGINAL.")
	}
}

// TestDataSize tests to make sure the data is larger the the aes.Blocksize (16
// bytes). If the data were smaller we wouldn't know if the GCM was working
// properly as it encrypts streams of data in 16-byte blocks.
func TestDataSize(t *testing.T) {
	if len(data) < aes.BlockSize {
		t.Error("TEST FAILED: DATA MUST BE LONGER THAN ", aes.BlockSize, " BYTES.")
	}
}

func handleErr(e error, t *testing.T) {
	if e != nil {
		(t.Error(e))
	}
}
