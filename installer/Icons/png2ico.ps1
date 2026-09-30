Add-Type -AssemblyName System.Drawing

$src = "E:\launcher\installer\Icons\app.png"
$dst = "E:\launcher\installer\Icons\app.ico"

$sizes = @(256, 128, 64, 48, 32, 16)

$srcBmp = [System.Drawing.Bitmap]::FromFile($src)

$bitmaps = @()
foreach ($s in $sizes) {
    $b = New-Object System.Drawing.Bitmap($s, $s)
    $g = [System.Drawing.Graphics]::FromImage($b)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.DrawImage($srcBmp, 0, 0, $s, $s)
    $g.Dispose()
    $bitmaps += $b
}

function GetPngBytes([System.Drawing.Bitmap]$bmp) {
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    return $ms.ToArray()
}

$out = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($out)

$header = New-Object byte[] 6
$header[0] = 0; $header[1] = 0
$header[2] = 1; $header[3] = 0
$header[4] = [byte]$bitmaps.Count; $header[5] = 0
$bw.Write($header)

$entryStart = 6 + 16 * $bitmaps.Count
$offset = $entryStart

for ($i = 0; $i -lt $bitmaps.Count; $i++) {
    $b = $bitmaps[$i]
    $side = if ($b.Width -ge 256) { 0 } else { $b.Width }
    $png = GetPngBytes $b
    $entry = New-Object byte[] 16
    $entry[0] = $side
    $entry[1] = $side
    $entry[2] = 0
    $entry[3] = 0
    $entry[4] = 1
    $entry[5] = 0
    $entry[6] = 32
    $entry[7] = 0
    $size = [uint32]$png.Length
    $off = [uint32]$offset
    $entry[8]= [byte]($size -band 0xff)
    $entry[9]= [byte](($size -shr 8) -band 0xff)
    $entry[10]= [byte](($size -shr 16) -band 0xff)
    $entry[11]= [byte](($size -shr 24) -band 0xff)
    $entry[12]= [byte]($off -band 0xff)
    $entry[13]= [byte](($off -shr 8) -band 0xff)
    $entry[14]= [byte](($off -shr 16) -band 0xff)
    $entry[15]= [byte](($off -shr 24) -band 0xff)
    $bw.Write($entry)
    $offset += $png.Length
}

for ($i = 0; $i -lt $bitmaps.Count; $i++) {
    $png = GetPngBytes $bitmaps[$i]
    $bw.Write($png)
}

$bw.Flush()
[System.IO.File]::WriteAllBytes($dst, $out.ToArray())

foreach ($b in $bitmaps) { $b.Dispose() }
$srcBmp.Dispose()

Write-Host "ICO written: $dst ($([Math]::Round((Get-Item $dst).Length / 1KB, 1)) KB)"
