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

// Package gencrypt provides methods for encrypting and decrypting data with
// the AES encryption method. Based on George Tankersley's talk at Gophercon
// 2016.
package gencrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// Galois implements the cipher.AEAD interface type (Authenticated Encryption
// with Associated Data), which allows us to seal and open streams of data,
// check overhead, and check the nonce size.
type Galois struct {
	GCM cipher.AEAD
}

// NewGCM takes a key and returns a new Galois struct. A 32-byte key is used to
// indicate AES-256. 16 and 24-byte keys are accepted for AES-128 and AES-192
// respectively, but are not recommended.
func NewGCM(key []byte) (*Galois, error) {
	g := &Galois{}
	// Here we retrieve a new cipher.Block using the key provided. block is a
	// 128-bit block cipher (cipher.Block) used for encrypting and decrypting
	// data in individual blocks. The mode implementations (e.g. Galois Counter
	// Mode) extend that capability to streams of blocks.
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return g, err
	}

	// We pass the cipher.Block to cipher.NewGCM() to retrieve a new GCM (Galois
	// Counter Mode).
	g.GCM, err = cipher.NewGCM(block)
	if err != nil {
		return g, err
	}

	// We return the Galois struct containing the GCM so that it can be used for
	// encryption and decryption by the client.
	return g, nil
}

// AESEncrypt is a method of the Galois struct which encrypts data using the
// mode (GCM) and returns an encrypted []byte.
func (g *Galois) AESEncrypt(data []byte) ([]byte, error) {
	// We use the gcm.NonceSize() method to create a byte slice with the
	// appropriate nonce length, then use the rand.Read() method to write random
	// bytes to the slice, thus creating our nonce.
	nonce := make([]byte, g.GCM.NonceSize())
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	// gcm.Seal() returns a []byte containing the encrypted data. The nonce is
	// used both as the dst []byte, which encrypted data is appended to, and to
	// derive the initial GCM counter state (for more details see the
	// cipher/gcm.go file in the Go source code).
	return g.GCM.Seal(nonce, nonce, data, nil), nil
}

// AESDecrypt is a method of the Galois struct which decrypts data using the
// mode (GCM) and returns a decrypted []byte, which can be converted to a type
// (e.g. string) of the original data.
func (g *Galois) AESDecrypt(data []byte) ([]byte, error) {
	// We return the decrypted data by passing it through gcm.Open(). Remember:
	// the data argument contains the nonce at the beginning of the slice, and
	// has the encrypted data appended after it, as seen below. The decrypted
	// data is returned as a []byte that can then be converted into its original
	// form.
	return g.GCM.Open(nil, data[:g.GCM.NonceSize()], data[g.GCM.NonceSize():], nil)
}
