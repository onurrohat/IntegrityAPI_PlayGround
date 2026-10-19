<#
.SYNOPSIS
  Sends a raw token obtained from the Play Integrity Standard API to Google's
  decodeIntegrityToken endpoint and returns the verdict (device/app/account integrity).

.NOTES
  Prerequisites:
   - The gcloud CLI is installed and "gcloud auth login" was run with a Google account
     that has Play Integrity API access under Play Console > Users and permissions.
   - The "Google Play Integrity API" is enabled in the Cloud project (Cloud Console > APIs & Services).
   - The Cloud project must be the same one whose number the app passes to
     PrepareIntegrityTokenRequest.setCloudProjectNumber().
   - The playintegrity scope cannot be obtained through a user login with gcloud's own
     (unverified) OAuth client (Google restricted-scope limitation). Therefore a service
     account is impersonated and a token with the "playintegrity" scope is requested
     explicitly through the IAM Credentials API (-ImpersonateServiceAccount).

.EXAMPLE
  ./decode-token.ps1 -PackageName com.onuroktayr.integrity -Token "eyJhbGciOi..." `
    -ImpersonateServiceAccount play-integrity-decoder@project-xxx.iam.gserviceaccount.com
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageName,

    [Parameter(Mandatory = $true)]
    [string]$Token,

    [string]$ImpersonateServiceAccount
)

if ($ImpersonateServiceAccount) {
    $callerToken = (gcloud auth print-access-token 2>$null)
    if (-not $callerToken) {
        Write-Error "Could not obtain a gcloud access token. Run 'gcloud auth login'."
        exit 1
    }

    $genUri = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$($ImpersonateServiceAccount):generateAccessToken"
    $genBody = @{ scope = @("https://www.googleapis.com/auth/playintegrity") } | ConvertTo-Json

    try {
        $genResponse = Invoke-RestMethod -Uri $genUri -Method Post `
            -Headers @{ Authorization = "Bearer $callerToken" } `
            -ContentType "application/json" `
            -Body $genBody
        $accessToken = $genResponse.accessToken
    }
    catch {
        Write-Error "generateAccessToken call failed: $($_.Exception.Message)"
        if ($_.ErrorDetails) { Write-Error $_.ErrorDetails.Message }
        exit 1
    }
}
else {
    $accessToken = (gcloud auth print-access-token 2>$null)
}

if (-not $accessToken) {
    Write-Error "Could not obtain a gcloud access token. Run 'gcloud auth login' and sign in with an account that has Play Integrity access."
    exit 1
}

$uri = "https://playintegrity.googleapis.com/v1/$($PackageName):decodeIntegrityToken"
$body = @{ integrity_token = $Token } | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri $uri -Method Post `
        -Headers @{ Authorization = "Bearer $accessToken" } `
        -ContentType "application/json" `
        -Body $body

    $response | ConvertTo-Json -Depth 10
}
catch {
    Write-Error "decodeIntegrityToken call failed: $($_.Exception.Message)"
    if ($_.ErrorDetails) { Write-Error $_.ErrorDetails.Message }
    exit 1
}
