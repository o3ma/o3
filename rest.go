package o3

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"errors"

	"github.com/o3ma/o3rest/apiclient_pkg"
	"github.com/o3ma/o3rest/models_pkg"
	"golang.org/x/crypto/nacl/box"
)

// ThreemaRest provides convinient wrappers for task that require the use of Threemas REST API
type ThreemaRest struct {
	client apiclient_pkg.APICLIENT_IMPL
}

// CreateIdentity generates a new NaCl Keypair, registers it with the Three servers and returns the assigned ID
func (tr ThreemaRest) CreateIdentity() (ThreemaID, error) {
	// Get Keypair and nonce ready
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return ThreemaID{}, err
	}

	pubkey := base64.StdEncoding.EncodeToString(publicKey[:])

	// The nonce is harcoded in threema
	nonce := [24]byte{0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x20, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e}

	// Request token and tokenRespKeyPub
	idCreateParams := models_pkg.CreateRequest{
		PublicKey: &pubkey}

	challenge, err := tr.client.IdentityCreate(&idCreateParams)
	if err != nil {
		return ThreemaID{}, err
	}

	// Decode token and tokenRespPub
	tokenRespKeyPub, err := base64.StdEncoding.DecodeString(*challenge.TokenRespKeyPub)
	if err != nil {
		return ThreemaID{}, err
	}
	var tokenPubKey [32]byte
	copy(tokenPubKey[:], tokenRespKeyPub[:32])

	token, err := base64.StdEncoding.DecodeString(*challenge.Token)
	if err != nil {
		return ThreemaID{}, err
	}

	// Compute the Response
	tokenResponse := base64.StdEncoding.EncodeToString(box.Seal(nil, []byte(token), &nonce, &tokenPubKey, privateKey))

	response := models_pkg.CreateStage2Request{
		PublicKey: &pubkey,
		Response:  &tokenResponse,
		Token:     challenge.Token}

	finalResult, err := tr.client.IdentityCreateStage2(&response)
	if err != nil {
		return ThreemaID{}, err
	}
	if !*finalResult.Success {
		panic("Server responded with error!")
	}

	fmt.Printf("New Identity: %s Server: %s\n", *finalResult.Identity, *finalResult.ServerGroup)
	fmt.Printf("PrivateKey: %x\n", *privateKey)
	fmt.Printf("PublicKey: %x\n", *publicKey)

	newID := ThreemaID{
		ID:   NewIdString(*finalResult.Identity),
		Nick: NewPubNick(*finalResult.Identity),
		LSK:  *privateKey}

	if !tr.setFeatureLevel(newID, 4) {
		return ThreemaID{}, errors.New("Failed to set feature level!")
	}

	return newID, nil

}

func (tr ThreemaRest) setFeatureLevel(thid ThreemaID, featurelevel int) (succes bool) {
	featureLevelFloat := float64(featurelevel)

	// The nonce is harcoded in threema
	nonce := [24]byte{0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x20, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x2e}
	nonceB64 := base64.StdEncoding.EncodeToString(nonce[:])

	idString := thid.String()
	request := models_pkg.SetFeaturelevelRequest{
		Identity:     &idString,
		FeatureLevel: &featureLevelFloat}

	challenge, err := tr.client.IdentitySetFeaturelevel(&request)

	// Decode token and tokenRespPub
	tokenRespKeyPub, err := base64.StdEncoding.DecodeString(*challenge.TokenRespKeyPub)
	if err != nil {
		return false
	}
	var tokenPubKey [32]byte
	copy(tokenPubKey[:], tokenRespKeyPub[:32])

	token, err := base64.StdEncoding.DecodeString(*challenge.Token)
	if err != nil {
		return false
	}

	// Compute the Response
	tokenResponse := base64.StdEncoding.EncodeToString(box.Seal(nil, []byte(token), &nonce, &tokenPubKey, &thid.LSK))

	response := models_pkg.SetFeaturelevelStage2Request{
		Response:     &tokenResponse,
		Identity:     &idString,
		Nonce:        &nonceB64,
		Token:        challenge.Token,
		FeatureLevel: &featureLevelFloat,
	}

	result, err := tr.client.IdentitySetFeaturelevelStage2(&response)

	return *result.Success
}

// GetContactByID returns a ThreemaContact containing the public key as queried from the Threema servers
func (tr ThreemaRest) GetContactByID(thIDString IdString) (ThreemaContact, error) {
	response, err := tr.client.IdentityById(thIDString.String())
	if err != nil {
		return ThreemaContact{}, err
	}

	pubKeyDecoded, err := base64.StdEncoding.DecodeString(*response.PublicKey)
	if err != nil {
		return ThreemaContact{}, err
	}
	var pubKey [32]byte
	copy(pubKey[:], (pubKeyDecoded[:32]))

	return ThreemaContact{
		ID:  [8]byte(thIDString),
		LPK: pubKey}, nil
}
