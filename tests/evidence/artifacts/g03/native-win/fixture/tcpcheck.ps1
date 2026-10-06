param([int]$Port)
$c = New-Object Net.Sockets.TcpClient
try { $c.Connect('127.0.0.1', $Port); $s = $c.GetStream(); $s.ReadTimeout = 5000; $b = New-Object byte[] 64; $n = $s.Read($b, 0, 64); 'banner: ' + [Text.Encoding]::ASCII.GetString($b, 0, $n).Trim() } catch { 'error: ' + $_.Exception.InnerException.Message } finally { $c.Dispose() }
