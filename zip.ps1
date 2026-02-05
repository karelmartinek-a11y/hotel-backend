$root = 'C:\\github\\hotel-backend'
$zip = 'C:\\github\\hotel-backend\\hotel-backend.zip'
$exclude = @('.git', 'venv', '.venv', 'env', 'LOG', 'LOGS', 'OUT', 'OUTPUT', 'IN', '__pycache__')
$files = Get-ChildItem -LiteralPath $root -Recurse -Force | Where-Object {
    if ($_.PSIsContainer) { return $false }
    $parts = ($_.FullName.Substring($root.Length)).TrimStart('\','/') -split '[\\/]'
    return -not ($parts | Where-Object { $exclude -contains $_ })
}
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path $files.FullName -DestinationPath $zip -Force -CompressionLevel Optimal
