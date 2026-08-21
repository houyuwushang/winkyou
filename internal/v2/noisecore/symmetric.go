package noisecore

import (
	"crypto/hmac"
	"crypto/sha256"
)

type symmetricState struct {
	chainingKey [HashSize]byte
	hash        [HashSize]byte
	cipher      cipherStateCore
}

func (state *symmetricState) initialize(protocolName string) {
	protocolBytes := []byte(protocolName)
	if len(protocolBytes) <= HashSize {
		copy(state.hash[:], protocolBytes)
	} else {
		state.hash = sha256.Sum256(protocolBytes)
	}
	state.chainingKey = state.hash
	state.cipher.initializeKey(nil)
}

func (state *symmetricState) mixHash(data []byte) {
	hash := sha256.New()
	_, _ = hash.Write(state.hash[:])
	_, _ = hash.Write(data)
	sum := hash.Sum(nil)
	copy(state.hash[:], sum)
	zeroBytes(sum)
}

func (state *symmetricState) mixKey(inputKeyMaterial []byte) {
	outputs := noiseHKDF(state.chainingKey[:], inputKeyMaterial, 2)
	state.chainingKey = outputs[0]
	state.cipher.initializeKey(outputs[1][:])
	zeroHKDFOutputs(&outputs)
}

func (state *symmetricState) mixKeyAndHash(inputKeyMaterial []byte) {
	outputs := noiseHKDF(state.chainingKey[:], inputKeyMaterial, 3)
	state.chainingKey = outputs[0]
	state.mixHash(outputs[1][:])
	state.cipher.initializeKey(outputs[2][:])
	zeroHKDFOutputs(&outputs)
}

func (state *symmetricState) encryptAndHash(plaintext []byte) ([]byte, error) {
	ciphertext, err := state.cipher.encryptWithAD(state.hash[:], plaintext)
	if err != nil {
		return nil, err
	}
	state.mixHash(ciphertext)
	return ciphertext, nil
}

func (state *symmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	plaintext, err := state.cipher.decryptWithAD(state.hash[:], ciphertext)
	if err != nil {
		return nil, err
	}
	state.mixHash(ciphertext)
	return plaintext, nil
}

func (state *symmetricState) split() ([HashSize]byte, [HashSize]byte, error) {
	outputs := noiseHKDF(state.chainingKey[:], nil, 2)
	first := outputs[0]
	second := outputs[1]
	zeroHKDFOutputs(&outputs)
	return first, second, nil
}

func (state *symmetricState) handshakeHash() [HashSize]byte {
	return state.hash
}

func (state *symmetricState) zeroize() {
	zeroBytes(state.chainingKey[:])
	zeroBytes(state.hash[:])
	state.cipher.zeroize()
}

func noiseHKDF(chainingKey, inputKeyMaterial []byte, outputs int) [3][HashSize]byte {
	var result [3][HashSize]byte
	tempKey := hmacSHA256(chainingKey, inputKeyMaterial)
	previous := []byte(nil)
	for index := 0; index < outputs; index++ {
		input := make([]byte, 0, len(previous)+1)
		input = append(input, previous...)
		input = append(input, byte(index+1))
		current := hmacSHA256(tempKey[:], input)
		result[index] = current
		zeroBytes(input)
		zeroBytes(current[:])
		previous = result[index][:]
	}
	zeroBytes(tempKey[:])
	return result
}

func hmacSHA256(key, data []byte) [HashSize]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	sum := mac.Sum(nil)
	var result [HashSize]byte
	copy(result[:], sum)
	zeroBytes(sum)
	return result
}

func zeroHKDFOutputs(outputs *[3][HashSize]byte) {
	for index := range outputs {
		zeroBytes(outputs[index][:])
	}
}
