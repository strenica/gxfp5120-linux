# psk-unseal-windows.ps1 — run this INSIDE WINDOWS (no password needed if the blob is
# machine-scope, which the evidence strongly suggests).
# Writes the 32-byte PSK to %USERPROFILE%\psk_raw32.bin

$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Security

function Hex2Bytes([string]$s) {
    $b = New-Object byte[] ($s.Length / 2)
    for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($s.Substring($i * 2, 2), 16) }
    return , $b
}

$Cache = Join-Path $env:ProgramData 'Goodix\Goodix_Cache.bin'
if (-not (Test-Path $Cache)) { Write-Host "cache not found: $Cache"; exit 1 }

$d = [IO.File]::ReadAllBytes($Cache)
$seed = $d[-8..-1]
$blob = $d[0..($d.Length - 9)]

$sha = [Security.Cryptography.SHA256]::Create()
$sh = $sha.ComputeHash($seed)
$c1 = Hex2Bytes '9d7992b38402b66c81d1f555218942a9'
$c2 = Hex2Bytes '1848d71550d270d219c80632ab4f8bb3'
$c3 = Hex2Bytes 'e47c8938db5250f0205617ee17da4eb4'

$rk = New-Object byte[] 16
for ($i = 0; $i -lt 8; $i++)  { $rk[$i] = $c1[$i] -bxor $c2[$i] -bxor $c1[$i + 8] }
for ($i = 8; $i -lt 16; $i++) { $rk[$i] = $c2[$i] -bxor $c3[$i] -bxor $c3[$i - 8] }
$ent = $sh[16..31] + $sha.ComputeHash($sh[0..15] + $rk)

$out = Join-Path $env:USERPROFILE 'psk_raw32.bin'
foreach ($s in 'CurrentUser', 'LocalMachine') {
    try {
        $p = [Security.Cryptography.ProtectedData]::Unprotect(
                 $blob, $ent, [Security.Cryptography.DataProtectionScope]::$s)
        [IO.File]::WriteAllBytes($out, $p)
        $h = [BitConverter]::ToString($sha.ComputeHash($p)) -replace '-', ''
        Write-Host "SUCCESS scope=$s bytes=$($p.Length)"
        Write-Host "written: $out"
        Write-Host "sha256:  $h"
        exit 0
    } catch {
        Write-Host "fail scope=$s : $($_.Exception.Message)"
    }
}
Write-Host 'Both scopes failed. Report this output.'
exit 1
