# Reconstruct ORIGINAL /system/lib64/libvulkan.so from add_needed.py-patched file.
# phdr layout (12): [0]PHDR [1]LOAD0 [2]LOAD(RX) [3]LOAD(0x34000,RW) [4]LOAD(0x358c8,dyn,RW) [5]DYNAMIC [6]RELRO [7]EH_FRAME [8]STACK [9]PROPERTY [10]NOTE [11]NOTE
$ErrorActionPreference = "Stop"
$src = "D:\wsl\renderdoc\libvulkan_device.so"
$dst = "D:\wsl\renderdoc\libvulkan_original_reconstructed.so"

$bytes = [byte[]][System.IO.File]::ReadAllBytes($src)

function U16([int]$o) { [BitConverter]::ToUInt16($bytes, $o) }
function U64([int]$o) { [BitConverter]::ToUInt64($bytes, $o) }
function W64([int]$off, [UInt64]$val) { [Array]::Copy([BitConverter]::GetBytes($val), 0, $bytes, $off, 8) }

$e_phoff = U64 0x20; $e_phentsize = U16 0x36; $e_phnum = U16 0x38
$e_shoff = U64 0x28; $e_shentsize = U16 0x3A; $e_shnum = U16 0x3C
$origSize = [int]($e_shoff + $e_shnum * $e_shentsize)
Write-Host "origSize=0x$($origSize.ToString('X'))"

# [0] PHDR: filesz/memsz = phnum * phentsize
$p0 = [int]($e_phoff + 0 * $e_phentsize); $phdrSz = [UInt64]($e_phnum * $e_phentsize)
W64 ($p0 + 32) $phdrSz; W64 ($p0 + 40) $phdrSz

# [1] LOAD0: filesz/memsz = 0x1400C
$p1 = [int]($e_phoff + 1 * $e_phentsize)
W64 ($p1 + 32) ([UInt64]0x1400C); W64 ($p1 + 40) ([UInt64]0x1400C)

# [3] LOAD@0x34000: filesz=0x1F68 memsz=0x2000
$p3 = [int]($e_phoff + 3 * $e_phentsize)
W64 ($p3 + 32) ([UInt64]0x1F68); W64 ($p3 + 40) ([UInt64]0x2000)

# [4] LOAD@0x38000 (.data/.bss tail): offset/vaddr/paddr=0x38000, filesz/memsz = origSize - 0x38000
$p4 = [int]($e_phoff + 4 * $e_phentsize)
$tailSz = [UInt64]($origSize - 0x38000)
W64 ($p4 + 8) ([UInt64]0x38000); W64 ($p4 + 16) ([UInt64]0x38000); W64 ($p4 + 24) ([UInt64]0x38000)
W64 ($p4 + 32) $tailSz; W64 ($p4 + 40) $tailSz

# [5] DYNAMIC: offset/vaddr/paddr=0x358C8 filesz/memsz=0x330
$p5 = [int]($e_phoff + 5 * $e_phentsize)
W64 ($p5 + 8) ([UInt64]0x358C8); W64 ($p5 + 16) ([UInt64]0x358C8); W64 ($p5 + 24) ([UInt64]0x358C8)
W64 ($p5 + 32) ([UInt64]0x330); W64 ($p5 + 40) ([UInt64]0x330)

# section [21] .dynamic: sh_addr/sh_offset=0x358C8 sh_size=0x330
$so = [int]($e_shoff + 21 * $e_shentsize)
W64 ($so + 16) ([UInt64]0x358C8); W64 ($so + 24) ([UInt64]0x358C8); W64 ($so + 32) ([UInt64]0x330)

# zero injected string at 0x1401C
for ($i = 0x1401C; $i -lt 0x1401C + 16; $i++) { $bytes[$i] = 0 }

# truncate
if ($bytes.Length -gt $origSize) { $bytes = [byte[]]$bytes[0..($origSize - 1)] }
[System.IO.File]::WriteAllBytes($dst, $bytes)
Write-Host "wrote $dst ($($bytes.Length) bytes)"
