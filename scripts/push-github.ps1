# Push MTProxyAutoSwitch fork to https://github.com/drew84kiss/MTProxyAutoSwitch
# Usage (PowerShell as Administrator recommended for hosts fix):
#   .\scripts\push-github.ps1 -Token "ghp_xxxxxxxx"
param(
    [Parameter(Mandatory = $true)]
    [string]$Token
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$hostsPath = "$env:WINDIR\System32\drivers\etc\hosts"
$oldApiIp = "144.31.14.104 api.github.com"
$newApiIp = "140.82.121.6 api.github.com"

function Fix-GitHubHosts {
    $content = Get-Content $hostsPath -Raw
    if ($content -notmatch [regex]::Escape($oldApiIp)) {
        Write-Host "Hosts: api.github.com entry already updated or missing."
        return
    }
    try {
        ($content -replace [regex]::Escape($oldApiIp), $newApiIp) | Set-Content $hostsPath -NoNewline
        Write-Host "Hosts: updated api.github.com -> 140.82.121.6"
    } catch {
        Write-Warning "Could not edit hosts (run PowerShell as Administrator). Trying push anyway..."
    }
}

Fix-GitHubHosts

Push-Location $repoRoot
try {
    $env:GH_TOKEN = $Token
    gh auth setup-git 2>$null
    git -c credential.helper= push "https://drew84kiss:$Token@github.com/drew84kiss/MTProxyAutoSwitch.git" main:main
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Remote repo may not exist yet. Creating..."
        gh repo create drew84kiss/MTProxyAutoSwitch --public --source=. --remote=origin --push --description "Fork MTProxy AutoSwitch v1.6 with local fixes"
    }
    Write-Host "Done: https://github.com/drew84kiss/MTProxyAutoSwitch"
} finally {
    Remove-Item Env:GH_TOKEN -ErrorAction SilentlyContinue
    Pop-Location
}
