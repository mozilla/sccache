##### Appveyor Rust Install Script #####

# This is the most important part of the Appveyor configuration. This installs the version of Rust
# specified by the "channel" and "target" environment variables from the build matrix. By default,
# Rust will be installed to C:\Rust for easy usage, but this path can be overridden by setting the
# RUST_INSTALL_DIR environment variable. The URL to download rust distributions defaults to
# https://static.rust-lang.org/dist/ but can overridden by setting the RUST_DOWNLOAD_URL environment
# variable.
#
# For simple configurations, instead of using the build matrix, you can override the channel and
# target environment variables with the --channel and --target script arguments.
#
# If no channel or target arguments or environment variables are specified, will default to stable
# channel and x86_64-pc-windows-msvc target.

param([string]$channel=${env:channel}, [string]$target=${env:target})

# Initialize our parameters from arguments and environment variables, falling back to defaults
if (!$channel) {
    $channel = "stable"
}
if (!$target) {
    $target = "x86_64-pc-windows-msvc"
}

$downloadUrl = "https://static.rust-lang.org/dist/"
if ($env:RUST_DOWNLOAD_URL) {
    $downloadUrl = $env:RUST_DOWNLOAD_URL
}

$installDir = "C:\Rust"
if ($env:RUST_INSTALL_DIR) {
    $installUrl = $env:RUST_INSTALL_DIR
}

# Download manifest so we can find actual filename of installer to download. Needed mostly for
# stable channel.
echo "Downloading $channel channel manifest"
$manifest = "${env:Temp}\channel-rust-${channel}"
Start-FileDownload "${downloadUrl}channel-rust-${channel}" -FileName "$manifest"

# Search the manifest lines for the correct filename based on target
$match = Get-Content "$manifest" | Select-String -pattern "${target}.exe" -simplematch

if (!$match -or !$match.line) {
    throw "Could not find $target in $channel channel manifest"
}

$installer = $match.line

# Download installer
echo "Downloading ${downloadUrl}$installer"
Start-FileDownload "${downloadUrl}$installer" -FileName "${env:Temp}\$installer"

# Execute installer and wait for it to finish
echo "Installing $installer to $installDir"
&"${env:Temp}\$installer" /VERYSILENT /NORESTART /DIR="$installDir" | Write-Output

# Add Rust to the path.
$env:Path += ";${installDir}\bin;C:\MinGW\bin"

echo "Installation of $channel Rust $target completed"

# Test and display installed version information for rustc and cargo
rustc -V
cargo -V