#http://jongurgul.com/blog/get-stringhash-get-filehash/
Function Get-StringHash([String] $String,$HashName = "MD5")
{
$StringBuilder = New-Object System.Text.StringBuilder
[System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{
[Void]$StringBuilder.Append($_.ToString("x2"))
}
$StringBuilder.ToString()
}

Function Check-Breached([String] $password)
{
    $thehash = Get-StringHash -String $password -HashName SHA1
    $header = @{ "user-agent" = "Powershell password hash query script github.com/pas3n7"}
    $firstfive = $thehash.substring(0,5)
    $suffix = $thehash.Substring(5,35)
    $response = Invoke-WebRequest -Headers $header -Uri "https://api.pwnedpasswords.com/range/$firstfive" -Method GET
    if ($response.content | Select-String -Pattern $suffix){
        $ispresent = $true
    } else {
        $ispresent = $false
    }
    return $ispresent

}

While($true){
$securepass = Read-Host "Enter the password you want to search for" -AsSecureString
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securepass)
$passtotest = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
 if (Check-Breached -password $passtotest){
    write-host "  Yes, that password WAS found in a breach `n"
 }
 else{
    write-host "  No, that password was NOT found in a breach `n"
 }


}

