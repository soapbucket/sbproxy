// Package manager defines the Manager interface for coordinating proxy lifecycle and configuration reloads.
package manager

// EncryptString performs the encrypt string operation on the managerImpl.
func (m *managerImpl) EncryptString(data string) (string, error) {
	result, err := m.crypto.Encrypt([]byte(data))
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// DecryptString performs the decrypt string operation on the managerImpl.
func (m *managerImpl) DecryptString(data string) (string, error) {
	result, err := m.crypto.Decrypt([]byte(data))
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// EncryptStringWithContext performs the encrypt string with context operation on the managerImpl.
func (m *managerImpl) EncryptStringWithContext(data string, context string) (string, error) {
	result, err := m.crypto.EncryptWithContext([]byte(data), context)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// DecryptStringWithContext performs the decrypt string with context operation on the managerImpl.
func (m *managerImpl) DecryptStringWithContext(data string, context string) (string, error) {
	result, err := m.crypto.DecryptWithContext([]byte(data), context)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// SignString performs the sign string operation on the managerImpl.
func (m *managerImpl) SignString(data string) (string, error) {
	result, err := m.crypto.Sign([]byte(data))
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// VerifyString performs the verify string operation on the managerImpl.
func (m *managerImpl) VerifyString(data string, signature string) (bool, error) {
	result, err := m.crypto.Verify([]byte(data), []byte(signature))
	if err != nil {
		return false, err
	}
	return result, nil
}
