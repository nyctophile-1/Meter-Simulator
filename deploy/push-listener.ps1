<#
.SYNOPSIS
    Minimal TCP push receiver for testing the simulator's on-demand push.

.DESCRIPTION
    Accepts connections and prints, per connection, the SOURCE address and the first bytes
    received. The source address is the point: it is how you verify that each meter pushed
    from its OWN IPv6 rather than all of them sharing the host's default address.

    Dual-mode, so one listener serves both an IPv4 destination (e.g. 127.0.0.1) and an IPv6
    destination (e.g. [fd00:6d65:7472::ffff]).

.EXAMPLE
    .\push-listener.ps1 -Port 9999
#>
param(
    [int]$Port = 9999,
    # Bytes of each frame to print as hex. The full length is always reported.
    [int]$PreviewBytes = 32
)

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::IPv6Any, $Port)
# Must be set before Start() — lets the same socket accept IPv4 (as ::ffff:a.b.c.d) too.
$listener.Server.DualMode = $true
$listener.Start()

Write-Host "Push listener on [::]:$Port (dual-mode). Ctrl+C to stop." -ForegroundColor Cyan
Write-Host ""

$count = 0
try {
    while ($true) {
        $client = $listener.AcceptTcpClient()
        $count++

        $source = $client.Client.RemoteEndPoint.Address
        $stream = $client.GetStream()
        $stream.ReadTimeout = 2000

        $buffer = New-Object byte[] 65535
        $read = 0
        try { $read = $stream.Read($buffer, 0, $buffer.Length) } catch { $read = 0 }

        $preview = ''
        if ($read -gt 0) {
            $preview = [BitConverter]::ToString($buffer, 0, [Math]::Min($read, $PreviewBytes))
        }

        "{0,4}  from {1,-42} {2,6} bytes  {3}" -f $count, $source, $read, $preview |
            Write-Host

        $client.Close()
    }
}
finally {
    $listener.Stop()
    Write-Host ""
    Write-Host "Stopped after $count connection(s)." -ForegroundColor Cyan
}
