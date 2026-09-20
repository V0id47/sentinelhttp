//go:build windows

package cli

import (
	"errors"
	"syscall"
	"unsafe"
)

var advapi32 = syscall.NewLazyDLL("advapi32.dll")
var convertSDDL = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
var setFileSecurity = advapi32.NewProc("SetFileSecurityW")
var localFree = syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")

// Go's 0600 mode is not a Windows ACL. Protect the empty temporary file
// before any report bytes are written, denying inherited directory grants.
func restrictTempFile(path string) error {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return err
	}
	sddl, err := syscall.UTF16PtrFromString("D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return err
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var descriptor uintptr
	ok, _, _ := convertSDDL.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 || descriptor == 0 {
		return errors.New("private_acl_invalid")
	}
	defer localFree.Call(descriptor)
	ok, _, _ = setFileSecurity.Call(uintptr(unsafe.Pointer(name)), 4, descriptor) // DACL_SECURITY_INFORMATION
	if ok == 0 {
		return errors.New("private_acl_failed")
	}
	return nil
}
