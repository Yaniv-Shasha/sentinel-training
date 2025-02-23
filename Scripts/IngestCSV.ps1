PARAM(
    [Parameter(Mandatory=$true)]$CustomerId, # The log lanlyics workspace ID
    [Parameter(Mandatory=$true)]$SharedKey # The log lanlyics WorkspaceId
)

# You can use an optional field to specify the timestamp from the data. If the time field is not specified, Azure Monitor assumes the time is the message ingestion time
#$TimeStampField = ""


# Download telemetry data and convert from CSV
#Invoke-WebRequest -Uri "https://raw.githubusercontent.com/javiersoriano/sentinel-training/main/Telemetry/solarigate_event.csv" -OutFile "query_data.csv"
#$file = "query_data.csv"
#$payload = Import-Csv $file 

# Create the function to create the authorization signature
Function Write-OMSLogfile {
    <#
    .SYNOPSIS
    Inputs a hashtable, date and workspace type and writes it to a Log Analytics Workspace.
    .DESCRIPTION
    Given a  value pair hash table, this function will write the data to an OMS Log Analytics workspace.
    Certain variables, such as Customer ID and Shared Key are specific to the OMS workspace data is being written to.
    This function will not write to multiple OMS workspaces.  BuildSignature and post-analytics function from Microsoft documentation
    at https://docs.microsoft.com/azure/log-analytics/log-analytics-data-collector-api
    .PARAMETER DateTime
    date and time for the log.  DateTime value
    .PARAMETER Type
    Name of the logfile or Log Analytics "Type".  Log Analytics will append _CL at the end of custom logs  String Value
    .PARAMETER LogData
    A series of key, value pairs that will be written to the log.  Log file are unstructured but the key should be consistent
    withing each source.
    .INPUTS
    The parameters of data and time, type and logdata.  Logdata is converted to JSON to submit to Log Analytics.
    .OUTPUTS
    The Function will return the HTTP status code from the Post method.  Status code 200 indicates the request was received.
    .NOTES
    Version:        2.0
    Author:         Travis Roberts
    Creation Date:  7/9/2018
    Purpose/Change: Crating a stand alone function    
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [datetime]$dateTime,
        [parameter(Mandatory = $true, Position = 1)]
        [string]$type,
        [Parameter(Mandatory = $true, Position = 2)]
        [psobject]$logdata,
        [Parameter(Mandatory = $true, Position = 3)]
        [string]$CustomerID,
        [Parameter(Mandatory = $true, Position = 4)]
        [string]$SharedKey
    )
    Write-Verbose -Message "DateTime: $dateTime"
    Write-Verbose -Message ('DateTimeKind:' + $dateTime.kind)
    Write-Verbose -Message "Type: $type"
    write-Verbose -Message "LogData: $logdata"   

    # Supporting Functions
    # Function to create the auth signature
    Function BuildSignature ($CustomerID, $SharedKey, $Date, $ContentLength, $Method, $ContentType, $Resource) {
        $xheaders = 'x-ms-date:' + $Date
        $stringToHash = $Method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $Resource
        $bytesToHash = [text.Encoding]::UTF8.GetBytes($stringToHash)
        $keyBytes = [Convert]::FromBase64String($SharedKey)
        $sha256 = New-Object System.Security.Cryptography.HMACSHA256
        $sha256.key = $keyBytes
        $calculateHash = $sha256.ComputeHash($bytesToHash)
        $encodeHash = [convert]::ToBase64String($calculateHash)
        $authorization = 'SharedKey {0}:{1}' -f $CustomerID, $encodeHash
        return $authorization
    }
    # Function to create and post the request
    Function PostLogAnalyticsData ($CustomerID, $SharedKey, $Body, $Type) {
        $method = "POST"
        $contentType = 'application/json'
        $resource = '/api/logs'
        $rfc1123date = ($dateTime).ToString('r')
        $ContentLength = $Body.Length
        $signature = BuildSignature `
            -customerId $CustomerID `
            -sharedKey $SharedKey `
            -date $rfc1123date `
            -contentLength $ContentLength `
            -method $method `
            -contentType $contentType `
            -resource $resource
        $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
		Write-Output "LA_URI : $uri"
        $headers = @{
            "Authorization"        = $signature;
            "Log-Type"             = $type;
            "x-ms-date"            = $rfc1123date
            "time-generated-field" = $dateTime
        }
        $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $Body -UseBasicParsing
        Write-Verbose -message ('Post Function Return Code ' + $response.statuscode)
        return $response.statuscode
    }   

    # Check if time is UTC, Convert to UTC if not.
    # $dateTime = (Get-Date)
    if ($dateTime.kind.tostring() -ne 'Utc') {
        $dateTime = $dateTime.ToUniversalTime()
        Write-Verbose -Message $dateTime
    }
    #Build the JSON file
    $logMessage = ($logdata | ConvertTo-Json -Depth 20)
    
    #Submit the data
    $returnCode = PostLogAnalyticsData -CustomerID $CustomerID -SharedKey $SharedKey -Body $logMessage -Type $type
    Write-Verbose -Message "Post Statement Return Code $returnCode"
    return $returnCode
}

Function SendToLogA ($url, $eventsTable) {    	
	Invoke-WebRequest -Uri $url -OutFile "query_data.csv"
    $eventsData = Import-Csv "query_data.csv"
    
    #Test Size; Log A limit is 30MB
    $tempdata = @()
    $tempDataSize = 0
    
    if ((($eventsData |  Convertto-json -depth 20).Length) -gt 25MB) {        
		Write-Host "Upload is over 25MB, needs to be split"									 
        foreach ($record in $eventsData) {            
            $tempdata += $record
            $tempDataSize += ($record | ConvertTo-Json -depth 20).Length
            if ($tempDataSize -gt 25MB) {
                $postLAStatus = Write-OMSLogfile -dateTime (Get-Date) -type $eventsTable -logdata $tempdata -CustomerID $CustomerId -SharedKey $SharedKey
                write-Host "Sending data = $TempDataSize"
                $tempdata = $null
                $tempdata = @()
                $tempDataSize = 0
            }
        }
        Write-Host "Sending left over data = $Tempdatasize"
        $postLAStatus = Write-OMSLogfile -dateTime (Get-Date) -type $eventsTable -logdata $tempdata -CustomerID $CustomerId -SharedKey $SharedKey
    }
    Else {          
        $postLAStatus = Write-OMSLogfile -dateTime (Get-Date) -type $eventsTable -logdata $eventsData -CustomerID $CustomerId -SharedKey $SharedKey        
    }
    
    Remove-Item "query_data.csv"

    return $postLAStatus
}

# Submit the data to the API endpoint
$status = SendToLogA -url "https://raw.githubusercontent.com/javiersoriano/sentinel-training/main/Telemetry/solarigate_CEFevent.csv" -EventsTable "CommonSecurityLog"

Write-Host $status

$status = SendToLogA -url "https://raw.githubusercontent.com/javiersoriano/sentinel-training/main/Telemetry/securityEvents.csv" -EventsTable "SecurityEvent"

Write-Host $status

$status = SendToLogA -url "https://raw.githubusercontent.com/javiersoriano/sentinel-training/main/Telemetry/disable_accounts.csv" -EventsTable "SigninLogs"

Write-Host $status

$status = SendToLogA -url "https://raw.githubusercontent.com/javiersoriano/sentinel-training/main/Telemetry/office_activity_inbox_rule.csv" -EventsTable "OfficeActivity"

Write-Host $status

$status = SendToLogA -url "https://raw.githubusercontent.com/javiersoriano/sentinel-training/main/Telemetry/azureActivity_adele.csv" -EventsTable "AzureActivity"

Write-Host $status

$status = SendToLogA -url "https://raw.githubusercontent.com/javiersoriano/sentinel-training/main/Telemetry/office_activity.csv" -EventsTable "OfficeActivity"

Write-Host $status

$status = SendToLogA -url "https://raw.githubusercontent.com/javiersoriano/sentinel-training/main/Telemetry/sign-in_adelete.csv" -EventsTable "SigninLogs"

Write-Host $status

Start-Sleep -Seconds 600