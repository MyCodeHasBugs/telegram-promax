Add-Type -AssemblyName System.Drawing

$src = "E:\launcher\installer\Icons\app.png"
$dst = "E:\launcher\installer\Icons\app.ico"

$bmp = [System.Drawing.Bitmap]::FromFile($src)
$hIcon = $bmp.GetHicon()
$icon = [System.Drawing.Icon]::FromHandle($hIcon)

$fs = [System.IO.File]::OpenWrite($dst)
$icon.Save($fs)
$fs.Close()

$bmp.Dispose()
$icon.Dispose()

Get-Item $dst | Select-Object Length
