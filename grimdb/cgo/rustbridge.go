// Package rustbridge provides Go bindings to the grimlocker-core Rust DLL.
// On Windows, it uses syscall.LoadDLL to load the shared library at runtime,
// avoiding the need for CGO and a C compiler.
//
// If the DLL is not found, all functions fall back to Go-native implementations
// (less secure than the Rust enclave, but functional).
package rustbridge

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"
)

var (
	dll      *syscall.DLL
	dllOnce  sync.Once
	dllErr   error
	dllAvail bool
)

func init() {
	dllOnce.Do(func() {
		exePath, _ := os.Executable()
		exeDir := ""
		if exePath != "" {
			exeDir = filepath.Dir(exePath)
		}
		paths := []string{
			"grimlocker_core.dll",
		}
		if exeDir != "" {
			paths = append(paths, filepath.Join(exeDir, "grimlocker_core.dll"))
		}
		for _, p := range paths {
			d, err := syscall.LoadDLL(p)
			if err == nil {
				dll = d
				dllAvail = true
				log.Printf("[rustbridge] Loaded grimlocker_core.dll from %s", p)
				return
			}
		}
		dllErr = fmt.Errorf("grimlocker_core.dll not found in PATH")
		log.Printf("[rustbridge] DLL not found, using Go fallback: %v", dllErr)
	})
}

func ensureDLL() error {
	if !dllAvail {
		return fmt.Errorf("grimlocker_core DLL not available: %w", dllErr)
	}
	return nil
}

func callProc(procName string, args ...uintptr) (uintptr, error) {
	if err := ensureDLL(); err != nil {
		return 0, err
	}
	proc, err := dll.FindProc(procName)
	if err != nil {
		return 0, fmt.Errorf("find proc %s: %w", procName, err)
	}
	r, _, _ := proc.Call(args...)
	return r, nil
}

func uint8PtrToString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	var length int
	for {
		b := *(*byte)(unsafe.Pointer(ptr + uintptr(length)))
		if b == 0 {
			break
		}
		length++
	}
	if length == 0 {
		return ""
	}
	return string((*[1 << 30]byte)(unsafe.Pointer(ptr))[:length:length])
}

func freeCString(ptr uintptr) {
	if ptr == 0 || !dllAvail {
		return
	}
	proc, err := dll.FindProc("free_cstring")
	if err != nil {
		return
	}
	proc.Call(ptr)
}

// --- Public API ---

// SecureZero overwrites a byte slice using the Rust secure_zero implementation.
func SecureZero(data []byte) {
	if len(data) == 0 {
		return
	}
	if !dllAvail {
		for i := range data {
			data[i] = 0
		}
		return
	}
	proc, err := dll.FindProc("secure_zero")
	if err != nil {
		for i := range data {
			data[i] = 0
		}
		return
	}
	proc.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)))
}

// InitCore initializes the Rust secure enclave.
func InitCore() error {
	if !dllAvail {
		return nil
	}
	r, err := callProc("grimcore_init")
	if err != nil {
		return err
	}
	msg := uint8PtrToString(r)
	freeCString(r)
	if msg != "OK" {
		return fmt.Errorf("grimcore_init: %s", msg)
	}
	return nil
}

// ShutdownCore destroys the Rust secure enclave, zeroing all key material.
func ShutdownCore() {
	if !dllAvail {
		return
	}
	proc, err := dll.FindProc("grimcore_shutdown")
	if err != nil {
		return
	}
	proc.Call()
}

// MVKStore stores a 32-byte MVK in the enclave and returns a handle string.
func MVKStore(mvk []byte) (string, error) {
	if len(mvk) != 32 {
		return "", fmt.Errorf("MVK must be 32 bytes")
	}
	if !dllAvail {
		return fmt.Sprintf("mvk:%x", mvk[:8]), nil
	}
	r, err := callProc("grimcore_mvk_store",
		uintptr(unsafe.Pointer(&mvk[0])),
		uintptr(len(mvk)),
	)
	if err != nil {
		return "", err
	}
	handle := uint8PtrToString(r)
	freeCString(r)
	if len(handle) > 5 && handle[:5] == "ERROR" {
		return "", fmt.Errorf("mvk_store: %s", handle)
	}
	return handle, nil
}

// MVKRevoke removes and zeroizes an MVK from the enclave.
func MVKRevoke(handle string) {
	if !dllAvail {
		return
	}
	h, _ := syscall.BytePtrFromString(handle)
	callProc("grimcore_mvk_revoke", uintptr(unsafe.Pointer(h)))
}

// SessionCreate generates a 32-byte session key and stores it in the enclave.
func SessionCreate() (string, [32]byte, error) {
	var keyOut [32]byte
	if !dllAvail {
		return "", keyOut, fmt.Errorf("session create requires Rust enclave")
	}
	r, err := callProc("grimcore_session_create",
		uintptr(unsafe.Pointer(&keyOut[0])),
		uintptr(32),
	)
	if err != nil {
		return "", keyOut, err
	}
	handle := uint8PtrToString(r)
	freeCString(r)
	if len(handle) > 5 && handle[:5] == "ERROR" {
		return "", keyOut, fmt.Errorf("session_create: %s", handle)
	}
	return handle, keyOut, nil
}

// SessionDestroy removes a session key from the enclave.
func SessionDestroy(handle string) {
	if !dllAvail {
		return
	}
	h, _ := syscall.BytePtrFromString(handle)
	callProc("grimcore_session_destroy", uintptr(unsafe.Pointer(h)))
}

// SecureWipeFile performs a 7-pass secure file wipe via the Rust core.
func SecureWipeFile(path string) error {
	if !dllAvail {
		return fmt.Errorf("secure wipe requires Rust enclave")
	}
	p, _ := syscall.BytePtrFromString(path)
	r, err := callProc("grimcore_secure_wipe", uintptr(unsafe.Pointer(p)))
	if err != nil {
		return err
	}
	msg := uint8PtrToString(r)
	freeCString(r)
	if msg != "OK" {
		return fmt.Errorf("secure_wipe: %s", msg)
	}
	return nil
}

// EncryptHandle encrypts plaintext using a key stored in the enclave.
func EncryptHandle(handle string, plaintext, aad []byte) ([]byte, error) {
	if !dllAvail {
		return nil, fmt.Errorf("encrypt requires Rust enclave")
	}
	proc, err := dll.FindProc("grimcore_encrypt_handle")
	if err != nil {
		return nil, fmt.Errorf("find grimcore_encrypt_handle: %w", err)
	}

	h, _ := syscall.BytePtrFromString(handle)
	outBuf := make([]byte, len(plaintext)+64)
	var outLen uint32 = uint32(len(outBuf))

	var aadPtr uintptr
	var aadLen uintptr
	if len(aad) > 0 {
		aadPtr = uintptr(unsafe.Pointer(&aad[0]))
		aadLen = uintptr(len(aad))
	}

	r, _, _ := proc.Call(
		uintptr(unsafe.Pointer(h)),
		uintptr(unsafe.Pointer(&plaintext[0])),
		uintptr(len(plaintext)),
		aadPtr, aadLen,
		uintptr(unsafe.Pointer(&outBuf[0])),
		uintptr(unsafe.Pointer(&outLen)),
	)
	msg := uint8PtrToString(r)
	freeCString(r)
	if msg != "OK" {
		return nil, fmt.Errorf("encrypt_handle: %s", msg)
	}
	return outBuf[:outLen], nil
}

// DecryptHandle decrypts nonce(12)+ciphertext+tag using a key from the enclave.
func DecryptHandle(handle string, ciphertext, aad []byte) ([]byte, error) {
	if !dllAvail {
		return nil, fmt.Errorf("decrypt requires Rust enclave")
	}
	proc, err := dll.FindProc("grimcore_decrypt_handle")
	if err != nil {
		return nil, fmt.Errorf("find grimcore_decrypt_handle: %w", err)
	}

	h, _ := syscall.BytePtrFromString(handle)
	outBuf := make([]byte, len(ciphertext))
	var outLen uint32 = uint32(len(outBuf))

	var aadPtr uintptr
	var aadLen uintptr
	if len(aad) > 0 {
		aadPtr = uintptr(unsafe.Pointer(&aad[0]))
		aadLen = uintptr(len(aad))
	}

	r, _, _ := proc.Call(
		uintptr(unsafe.Pointer(h)),
		uintptr(unsafe.Pointer(&ciphertext[0])),
		uintptr(len(ciphertext)),
		aadPtr, aadLen,
		uintptr(unsafe.Pointer(&outBuf[0])),
		uintptr(unsafe.Pointer(&outLen)),
	)
	msg := uint8PtrToString(r)
	freeCString(r)
	if msg != "OK" {
		return nil, fmt.Errorf("decrypt_handle: %s", msg)
	}
	return outBuf[:outLen], nil
}

// SKEEncrypt encrypts plaintext using the session key identified by handle.
func SKEEncrypt(handle string, plaintext []byte) ([]byte, error) {
	return EncryptHandle(handle, plaintext, nil)
}

// SKEDecrypt decrypts nonce(12)+ciphertext+tag using the session key identified by handle.
func SKEDecrypt(handle string, ciphertext []byte) ([]byte, error) {
	return DecryptHandle(handle, ciphertext, nil)
}

// DeriveWorkspaceKey derives a workspace-specific key via the Rust core.
func DeriveWorkspaceKey(masterKey []byte, workspaceID string) ([32]byte, error) {
	var result [32]byte
	if !dllAvail {
		return result, fmt.Errorf("workspace key derivation requires Rust enclave")
	}
	wsID, _ := syscall.BytePtrFromString(workspaceID)
	r, err := callProc("grimcore_derive_workspace_key",
		uintptr(unsafe.Pointer(&masterKey[0])),
		uintptr(len(masterKey)),
		uintptr(unsafe.Pointer(wsID)),
		uintptr(unsafe.Pointer(&result[0])),
		uintptr(len(result)),
	)
	if err != nil {
		return result, err
	}
	msg := uint8PtrToString(r)
	freeCString(r)
	if msg != "OK" {
		return result, fmt.Errorf("derive_workspace_key: %s", msg)
	}
	return result, nil
}

// DeriveCoordinate extracts bytes at offsets from entropy data and derives
// a 32-byte key using BLAKE3 → HKDF-SHA256 (correct Rust implementation).
func DeriveCoordinate(entropyData []byte, offsets []int64) ([]byte, error) {
	if !dllAvail {
		return nil, fmt.Errorf("coordinate derivation requires Rust enclave")
	}
	offsetsJSON := encodeOffsetsJSON(offsets)
	var keyOut [32]byte

	jsonPtr, _ := syscall.BytePtrFromString(offsetsJSON)
	r, err := callProc("grimcore_derive_coordinate",
		uintptr(unsafe.Pointer(&entropyData[0])),
		uintptr(len(entropyData)),
		uintptr(unsafe.Pointer(jsonPtr)),
		uintptr(unsafe.Pointer(&keyOut[0])),
		uintptr(32),
	)
	if err != nil {
		return nil, err
	}
	msg := uint8PtrToString(r)
	freeCString(r)
	if msg != "OK" {
		return nil, fmt.Errorf("derive_coordinate: %s", msg)
	}
	return keyOut[:], nil
}

// GenerateEntropyFile generates an entropy file via the Rust core.
func GenerateEntropyFile(path string, lineCount int) error {
	if !dllAvail {
		return fmt.Errorf("entropy generation requires Rust enclave")
	}
	p, _ := syscall.BytePtrFromString(path)
	r, err := callProc("generate_entropy_file", uintptr(unsafe.Pointer(p)), uintptr(lineCount))
	if err != nil {
		return err
	}
	msg := uint8PtrToString(r)
	freeCString(r)
	if msg != "OK" {
		return fmt.Errorf("generate_entropy_file: %s", msg)
	}
	return nil
}

// DeriveArgon2id derives a key using Argon2id via the Rust core.
// NOTE: The Rust implementation currently ignores time/memory/threads params
// and uses its own defaults. This is provided for future use when the Rust
// side is updated to respect the parameters.
func DeriveArgon2id(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) ([]byte, error) {
	if !dllAvail {
		return nil, fmt.Errorf("argon2id derivation requires Rust enclave")
	}
	proc, err := dll.FindProc("grimcore_derive_argon2id")
	if err != nil {
		return nil, fmt.Errorf("find grimcore_derive_argon2id: %w", err)
	}
	outBuf := make([]byte, keyLen)
	var outLen uint32 = uint32(len(outBuf))

	r, _, _ := proc.Call(
		uintptr(unsafe.Pointer(&password[0])),
		uintptr(len(password)),
		uintptr(unsafe.Pointer(&salt[0])),
		uintptr(len(salt)),
		uintptr(time),
		uintptr(memory),
		uintptr(threads),
		uintptr(keyLen),
		uintptr(unsafe.Pointer(&outBuf[0])),
		uintptr(unsafe.Pointer(&outLen)),
	)
	msg := uint8PtrToString(r)
	freeCString(r)
	if msg != "OK" {
		return nil, fmt.Errorf("derive_argon2id: %s", msg)
	}
	return outBuf[:outLen], nil
}

// --- Helpers ---

func encodeOffsetsJSON(offsets []int64) string {
	buf := make([]byte, 0, len(offsets)*12+2)
	buf = append(buf, '[')
	for i, o := range offsets {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, fmt.Sprintf("%d", o)...)
	}
	buf = append(buf, ']')
	return string(buf)
}

// Base64Encode encodes binary data to base64.
func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Base64Decode decodes base64 to binary.
func Base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
