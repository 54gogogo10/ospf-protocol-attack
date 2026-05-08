param(
    [string]$Arch = "amd64"
)

$ErrorActionPreference = "Stop"

Write-Host "Building OSPF Attack Simulator..." -ForegroundColor Cyan

if (-not (Test-Path "assets/npcap-installer.exe")) {
    Write-Warning "assets/npcap-installer.exe not found -- Npcap auto-install disabled."
}

pyinstaller `
    --onefile `
    --name "ospf-attack" `
    --add-binary "assets/npcap-installer.exe;." `
    --hidden-import scapy.contrib.ospf `
    --hidden-import scapy.layers.l2 `
    --hidden-import scapy.layers.inet `
    --hidden-import pcap `
    --hidden-import click `
    --hidden-import yaml `
    --clean `
    ospf_attack/cli/main.py

$size = (Get-Item "dist/ospf-attack.exe").Length / 1MB
Write-Host "Build complete: dist/ospf-attack.exe ($([math]::Round($size, 1)) MB)" -ForegroundColor Green
