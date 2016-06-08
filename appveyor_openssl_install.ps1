# Install OpenSSL (hopefully not permanent)
if ($env:target -match "-msvc$") {

$installer = "Win64OpenSSL-1_0_2h.exe"
$url = "https://slproweb.com/download/$installer"

# Download installer
echo "Downloading $url"
Start-FileDownload "$url" -FileName "${env:Temp}\$installer"

# Execute installer and wait for it to finish
echo "Installing $installer"
&"${env:Temp}\$installer" /VERYSILENT /SP- | Write-Output

# Set INCLUDE/LIB dirs appropriately.
$env:OPENSSL_INCLUDE_DIR = "c:\OpenSSL-Win64\include"
$env:OPENSSL_LIB_DIR = "c:\OpenSSL-Win64\lib"
$env:OPENSSL_LIBS = "ssleay32:libeay32"
$env:Path += ";c:\OpenSSL-Win64\bin"

echo "Installation of OpenSSL completed"
}