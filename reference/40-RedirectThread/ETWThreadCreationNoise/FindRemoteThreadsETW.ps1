# Start a trace listening to a provider with some thread creation events
# logman start ProcessActivityTrace -p "Microsoft-Windows-Kernel-Process" 0x30 -ets -o C:tempProcessActivity.etl -max 512

# Let it run for a few seconds
# logman stop ProcessActivityTrace -ets

# convert to a more viewable and parsable format
# tracerpt C:tempProcessActivity.etl -o C:tempProcessActivity.xml -of XML

# Analyze a "Microsoft-Windows-Kernel-Process" etw trace, for thread creation across processes.

param(
    [Parameter(Mandatory=$true)]
    [string]$XmlFilePath = "C:tempSystemActivity_New.xml" # Specify the path to your XML file
)

if (-not (Test-Path -Path $XmlFilePath)) {
    Write-Error "XML file not found: $XmlFilePath"
    return
}

Write-Host "Loading and analyzing '$XmlFilePath'..."

# Load the XML (use -Raw for large files)
try {
    [xml]$xmlDoc = Get-Content -Path $XmlFilePath -Raw -ErrorAction Stop
} catch {
    Write-Error "Failed to load or parse XML file '$XmlFilePath'. Error: $_"
    return
}

$remoteThreadEvents = @()

# Loop through each event
foreach ($event in $xmlDoc.Events.Event) {
    # Check for ThreadStart Task (3) and Opcode (1)
    if ($event.System.Task -eq '3' -and $event.System.Opcode -eq '1') {

        # Get Creator Process ID (from System section)
        $creatorPidStr = $null
        if ($event.System.Execution -ne $null) {
            $creatorPidStr = $event.System.Execution.ProcessID
        }

        # Get Target Process ID (from EventData section)
        $targetPidStr = $null
        if ($event.EventData -ne $null -and $event.EventData.Data -ne $null) {
            # Find the Data element specifically named "ProcessID"
            $targetPidData = $event.EventData.Data | Where-Object { $_.Name -eq 'ProcessID' } | Select-Object -First 1
            if ($targetPidData -ne $null) {
                $targetPidStr = $targetPidData.'#text'
            }
        }

        # Get Timestamp
        $timestamp = $null
        if ($event.System.TimeCreated -ne $null) {
           $timestamp = $event.System.TimeCreated.SystemTime
        }

        # Convert PIDs to integers for comparison (handle potential conversion errors)
        $creatorPid = $null
        $targetPid = $null
        $isValid = $true
        try {
            if ($creatorPidStr -ne $null) { $creatorPid = [int]$creatorPidStr } else { $isValid = $false }
            if ($targetPidStr -ne $null) { $targetPid = [int]$targetPidStr } else { $isValid = $false }
        } catch {
            # Write-Warning "Error converting PID at Timestamp $timestamp : $_" # Optional: show conversion errors
            $isValid = $false
        }

        # If PIDs are valid and different, it's a remote thread
        if ($isValid -and $creatorPid -ne $targetPid) {
            $result = [PSCustomObject]@{
                Timestamp     = $timestamp
                CreatorPID    = $creatorPid
                TargetPID     = $targetPid
            }
            $remoteThreadEvents += $result
        }
    }
}

# Display results
if ($remoteThreadEvents.Count -gt 0) {
    Write-Host "`n--- Detected Remote Thread Creation Events ---" -ForegroundColor Green
    $remoteThreadEvents | Format-Table -AutoSize
} else {
    Write-Host "`nNo remote thread creation events found in the log." -ForegroundColor Yellow
}

Write-Host "Analysis complete."
