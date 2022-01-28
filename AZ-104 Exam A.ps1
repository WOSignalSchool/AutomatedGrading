# Install-Module Microsoft.Graph -Scope CurrentUser
Import-Module Az -SkipEditionCheck
$subscription = Get-AzSubscription | Select -Last 1
Set-AzContext -SubscriptionObject $subscription 

$resourceGroup = Get-AzResourceGroup -Name *woac*
$resources = Get-AzResource -ResourceGroupName $resourceGroup.ResourceGroupName

$virtualMachine = Get-AzVM -ResourceGroupName $resourceGroup.ResourceGroupName

$publicIp = Get-AzPublicIpAddress -ResourceGroupName $resourceGroup.ResourceGroupName

$storageAccount = Get-AzStorageAccount -ResourceGroupName $resourceGroup.ResourceGroupName
$storageAccountKeys = Get-AzStorageAccountKey -ResourceGroupName $resourceGroup.ResourceGroupName -Name $storageAccount.StorageAccountName

$appService = Get-AzWebApp -ResourceGroupName $resourceGroup.ResourceGroupName
$appServiceConfig = $appService.SiteConfig

$appServicePlan = Get-AzAppServicePlan -ResourceGroupName $resourceGroup.ResourceGroupName 

$keyVault = Get-AzKeyVault -ResourceGroupName $resourceGroup.ResourceGroupName

$secrets = Get-AzKeyVaultSecret -VaultName $keyVault.VaultName
# $secretValues = Get-AzKeyVaultSecret -VaultName $keyVault.VaultName | ForEach-Object {(Get-AzKeyVaultSecret -VaultName $_.VaultName -Name $_.Name).SecretValue | ConvertFrom-SecureString -AsPlainText   }
$secretInfos = [System.Collections.ArrayList]::new()

foreach ($secret in $secrets) {
    $secretInfo = New-Object -Property @{Vault=$null;SecretName=$null; SecretValue=$null} -TypeName PSCustomObject
    $secretInfo.Vault = $secret.VaultName
    $secretInfo.SecretName = $secret.Name
    $secretInfo.SecretValue = (Get-AzKeyVaultSecret -VaultName $secret.VaultName -Name $secret.Name).SecretValue | ConvertFrom-SecureString -AsPlainText
    $secretInfos.Add($secretInfo) | Out-Null
}


function Calculate-Score {
    [CmdletBinding()]
    param (
        [Parameter()]
        [int]
        $MinScore,
        [Parameter()]
        [int]
        $MaxScore,
        [Parameter(ValueFromPipeline=$true)]
        [bool]
        $Result
    )
    begin {

    }
    
    process {
        if ($Result) {
            return $MaxScore
        } else {
            return $MinScore
        }
    }
    
    end {
        
    }
}


function Test-Condition {
    [CmdletBinding()]
    param (
        # This is the object that needs inspected
        [Parameter(ParameterSetName = "Default")]
        [object]
        $ReferenceObject,
        # This is the value that is expected for the object
        [Parameter(ParameterSetName = "Default")]
        [object]
        $ExpectedValue,
        # Use this to see if the expectedValue is within the reference object
        [Parameter(ParameterSetName = "Default")]
        [Parameter(ParameterSetName = "Contains")]
        [Switch]
        $Contains,
        # Use this to see if the expectedValue equals the reference object
        [Parameter(ParameterSetName = "Default")]
        [Parameter(ParameterSetName = "Equals")]
        [Switch]
        $Equals,
        [Parameter(ParameterSetName = "Default")]
        [Switch]
        $CaseSensitive
    )

    [bool]$result = $false
    $compareResult = $null

    $caseSensitivity = [System.StringComparison]::OrdinalIgnoreCase
    if ($CaseSensitive) {
        $caseSensitivity = [System.StringComparison]::Ordinal
    }

    if ($Contains) {

        if (($ReferenceObject -is [string]) -and ($ExpectedValue -is [string])) {
            Write-Verbose "Comparing Strings"
            $result = [bool]$ReferenceObject.Contains($ExpectedValue,$caseSensitivity )
        }
        else {
            Write-Verbose "Not a string"
            $compareResult = Compare-object -ReferenceObject $ReferenceObject -DifferenceObject $ExpectedValue -CaseSensitive:$CaseSensitive | Where SideIndicator -eq "=>"
            if ($null -eq $compareResult) {
                $result = $true
            }
        }
    }

    if ($Equals) {
        Write-Verbose "Performing Equals"

        $compareResult = Compare-Object -ReferenceObject $ReferenceObject -DifferenceObject $ExpectedValue
        if ($null -eq $compareResult) {
            $result = $true
        }
    }
        
    if ($result -eq $true) {
        return $result
        continue
    }
    
    return [bool]$result
}

Test-Condition -ReferenceObject @(1,2,3) -Contains -ExpectedValue 1 
Test-Condition -ReferenceObject @(1,2,3) -Contains -ExpectedValue @(1,2,3,4)
Test-Condition -ReferenceObject @(1,2,3,4) -Contains -ExpectedValue @(1,2,3)
Test-Condition -ReferenceObject "test" -Contains -ExpectedValue "te"
Test-Condition -ReferenceObject "test" -Contains -ExpectedValue "TE" -CaseInsensitive


Test-Condition -ReferenceObject @(1,2,3) -Equals -ExpectedValue @(1,2,3)
Test-Condition -ReferenceObject "test" -Equals -ExpectedValue "te"
Test-Condition -ReferenceObject "test" -Equals -ExpectedValue "test"
Test-Condition -ReferenceObject 1 -Equals -ExpectedValue 1
Test-Condition -ReferenceObject 1 -Equals -ExpectedValue 12


##Start Grading
Write-Host Section 1 -ForegroundColor Magenta
Test-Condition -ReferenceObject $resourceGroup.ResourceGroupName -Contains -ExpectedValue "exam" | Calculate-Score -MinScore 0 -MaxScore 15
Write-Host Section 2 -ForegroundColor Magenta
Write-Host Section 3 -ForegroundColor Magenta
Write-Host Section 4 -ForegroundColor Magenta
Test-Condition -ReferenceObject $secretInfos.SecretName -Contains -ExpectedValue "StorageAccount--Key1" -CaseSensitive | Calculate-Score -MinScore 0 -MaxScore 1
Test-Condition -ReferenceObject $secretInfos.SecretName -Contains -ExpectedValue "StorageAccount--Key2" -CaseSensitive | Calculate-Score -MinScore 0 -MaxScore 1
Test-Condition -ReferenceObject $secretInfos.SecretName -Contains -ExpectedValue "AzureVM--Username" -CaseSensitive | Calculate-Score -MinScore 0 -MaxScore 1
Test-Condition -ReferenceObject $secretInfos.SecretName -Contains -ExpectedValue "AzureVM--Password" -CaseSensitive | Calculate-Score -MinScore 0 -MaxScore 1
Write-Host Section 5 -ForegroundColor Magenta
Test-Condition -ReferenceObject $appServicePlan.Sku.Size -Equals -ExpectedValue "B1" | Calculate-Score -MinScore 0 -MaxScore 2
Write-Host Section 6 -ForegroundColor Magenta
Write-Host Section 7 -ForegroundColor Magenta