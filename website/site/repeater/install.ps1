# streetCryptid repeater for Windows: download the installer for this PC, check it, and run it.
#
#   irm https://streetcrypt.id/repeater/install.ps1 | iex
#
# Or, to read this script before anything runs (the guide at https://streetcrypt.id/repeater shows
# the same):
#
#   irm https://streetcrypt.id/repeater/install.ps1 -OutFile install.ps1
#   notepad install.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
#
# What it does, all of it:
#   1. Picks x64 or ARM64 from the machine's native architecture (not this shell's, which on an
#      ARM64 PC can be an emulated x64 process).
#   2. Downloads that installer from the project's GitHub releases (the `repeater-preview` feed the
#      app itself updates from) into a new folder in your temp folder, over HTTPS only, and only
#      from GitHub: a download redirected anywhere else is refused before a byte is saved.
#   3. Checks it before it runs. Its SHA-256 must match the checksum published in the same release
#      (`<installer>.sha256`, else that installer's line in the release's `SHA256SUMS`), and a
#      signature on it must be valid. Anything else deletes the file and stops.
#   4. Marks the file as downloaded from the internet, exactly as a browser would, and opens it.
#
# Step 4 is deliberate. The preview installers are not code-signed yet, so Windows SmartScreen
# will say it does not recognise the app. A file fetched by a script carries no such mark and
# would skip that check silently; we would rather you see the warning and choose. Click
# "More info", check the publisher line reads "Unknown publisher", then "Run anyway".
#
# The checksum comes from the same release as the installer, so it proves the file arrived intact
# and unaltered on the way, not who published it; a code signature will, once releases are signed.
#
# Nothing here needs administrator rights. Running as a Windows service is offered by the app's
# own setup, which asks for approval itself.
#
# Source: https://github.com/unrealJune/streetCryptid/blob/main/website/site/repeater/install.ps1

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue' # Windows PowerShell 5.1 downloads ~50x slower with the bar.

    # Windows PowerShell 5.1 can default to TLS 1.0, which GitHub refuses.
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    # GitHub serves a release asset from github.com by redirecting to its download hosts.
    $githubHosts = @(
        'github.com',
        'objects.githubusercontent.com',
        'release-assets.githubusercontent.com',
        'github-releases.githubusercontent.com'
    )

    # Download $Url to $OutFile only if it was fetched over HTTPS from GitHub, redirects included:
    # the final address is checked before anything is written.
    function Save-FromGitHub([string]$Url, [string]$OutFile) {
        $uri = [Uri]$Url
        if ($uri.Scheme -ne 'https' -or $githubHosts -notcontains $uri.Host) {
            throw "Refusing to download from $Url`: only HTTPS from GitHub."
        }
        $request = [Net.HttpWebRequest]::Create($uri)
        $request.AllowAutoRedirect = $true
        $request.UserAgent = 'streetcryptid-repeater-install'
        $response = $request.GetResponse()
        try {
            $final = $response.ResponseUri
            if ($final.Scheme -ne 'https' -or $githubHosts -notcontains $final.Host) {
                throw "The download of $Url was redirected to $($final.Scheme)://$($final.Host)/, not GitHub over HTTPS; nothing was saved."
            }
            $body = $response.GetResponseStream()
            $file = [IO.File]::Create($OutFile)
            try { $body.CopyTo($file) } finally { $file.Dispose(); $body.Dispose() }
        } finally {
            $response.Close()
        }
    }

    # The native architecture, from the one place emulation does not rewrite it.
    $arch = $null
    try {
        $arch = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name PROCESSOR_ARCHITECTURE).PROCESSOR_ARCHITECTURE
    } catch { }
    if (-not $arch) {
        $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    }
    switch ($arch) {
        'AMD64' { $rid = 'win-x64' }
        'ARM64' { $rid = 'win-arm64' }
        default { throw "The streetCryptid repeater runs on 64-bit Windows (x64 or ARM64); this PC reports '$arch'." }
    }

    $name = "StreetCryptid.Repeater-repeater-$rid-Setup.exe"
    $release = 'https://github.com/unrealJune/streetCryptid/releases/download/repeater-preview'
    $url = "https://github.com/unrealJune/streetCryptid/releases/download/repeater-preview/$name"
    # A folder of its own, not a fixed name in %TEMP% something else could have put there first.
    $folder = Join-Path ([IO.Path]::GetTempPath()) ("streetcryptid-repeater-" + [IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $folder | Out-Null
    $dest = Join-Path $folder $name

    Write-Host "streetCryptid repeater: downloading the $rid installer..."
    Save-FromGitHub $url $dest

    # The published SHA-256: `<installer>.sha256` (a bare hash, or `hash  name`), else the
    # installer's own line in `SHA256SUMS`.
    $expected = $null
    $sums = Join-Path $folder 'checksum.txt'
    try {
        Save-FromGitHub "$release/$name.sha256" $sums
        $text = [IO.File]::ReadAllText($sums)
        if ($text -match '(?m)^\s*([0-9A-Fa-f]{64})\b') { $expected = $Matches[1] }
    } catch [Net.WebException] {
        try {
            Save-FromGitHub "$release/SHA256SUMS" $sums
            foreach ($line in [IO.File]::ReadAllLines($sums)) {
                if ($line -match '^\s*([0-9A-Fa-f]{64})\s+\*?(.+?)\s*$' -and $Matches[2] -eq $name) {
                    $expected = $Matches[1]
                    break
                }
            }
        } catch [Net.WebException] { }
    }
    $actual = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
    if (-not $expected -or $actual -ne $expected) {
        Remove-Item -LiteralPath $folder -Recurse -Force
        if (-not $expected) {
            throw "The release publishes no checksum for $name, so the installer was not started. Try again in a few minutes (the feed may be mid-update), or download it from https://streetcrypt.id/repeater yourself."
        }
        throw "The installer does not match its published checksum (got $actual, expected $expected), so it was deleted and not started. Try again in a few minutes: the feed may be mid-update."
    }
    Write-Host "Checksum matches the release: SHA-256 $actual"

    # Preview builds are unsigned. A signature that is present must be valid: a broken or
    # untrusted one means the file is not what its signer shipped.
    $signature = Get-AuthenticodeSignature -LiteralPath $dest
    switch ($signature.Status) {
        'Valid' { Write-Host "Signed by $($signature.SignerCertificate.Subject)" }
        'NotSigned' { }
        default {
            Remove-Item -LiteralPath $folder -Recurse -Force
            throw "The installer's signature is $($signature.Status), so it was deleted and not started."
        }
    }
    Remove-Item -LiteralPath $sums -ErrorAction SilentlyContinue

    # The Mark of the Web, as a browser writes it. If it cannot be written, do not run the file:
    # that would be the silent bypass this script exists not to do.
    try {
        $zone = "[ZoneTransfer]`r`nZoneId=3`r`nReferrerUrl=https://streetcrypt.id/repeater`r`nHostUrl=$url`r`n"
        Set-Content -LiteralPath $dest -Stream Zone.Identifier -Value $zone
    } catch {
        Write-Warning "Could not mark the installer as downloaded, so it was not started. Open it yourself from: $dest"
        Start-Process -FilePath 'explorer.exe' -ArgumentList "/select,`"$dest`""
        return
    }

    Write-Host 'Starting the installer. Windows will ask before running an unsigned preview.'
    Start-Process -FilePath $dest
}
