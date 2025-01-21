Param(
    [Parameter(Mandatory=$false)]
    [string]
    $cudaVersion="12.6.0"
)

# Use System.Version to tokenize version
$version = [Version]$cudaVersion

$major = $version.Major
$minor = $version.Minor
$build = $version.Build

# Minimum build is 0, not -1 as default in case "12.5" is passed
if ($build -lt 0) {
    $build = 0
}

# mmb == major minor build
$mmbVersionTag = "${major}.${minor}.${build}"
# mm = major minor
$mmVersionTag = "${major}.${minor}"

$cudaVersionUrl = "https://developer.download.nvidia.com/compute/cuda/${mmbVersionTag}/network_installers/cuda_${mmbVersionTag}_windows_network.exe"

###
# `cuda_${mmbVersionTag}_windows_network.exe` name only valid back to CUDA v11.5.1.
# Before that it was named `cuda_${mmbVersionTag}_win10_network.exe`:
# * https://developer.download.nvidia.com/compute/cuda/11.5.1/network_installers/cuda_11.5.1_windows_network.exe
# * https://developer.download.nvidia.com/compute/cuda/11.5.0/network_installers/cuda_11.5.0_win10_network.exe
###

if ([version]$mmbVersionTag -le "11.5.0") {
    $cudaVersionUrl = "https://developer.download.nvidia.com/compute/cuda/${mmbVersionTag}/network_installers/cuda_${mmbVersionTag}_win10_network.exe"
}

$cudaComponents =
    "nvcc_$mmVersionTag",
    "curand_$mmVersionTag",
    "curand_dev_$mmVersionTag",
    "cudart_$mmVersionTag",
    "cupti_$mmVersionTag",
    "nvrtc_$mmVersionTag",
    "nvrtc_dev_$mmVersionTag",
    "nvml_dev_$mmVersionTag",
    "nvtx_$mmVersionTag"

Invoke-WebRequest -Uri "$cudaVersionUrl" -OutFile "./cuda_network.exe" -UseBasicParsing
Start-Process -Wait -PassThru -FilePath .\cuda_network.exe -ArgumentList "-s $cudaComponents"

$ENV:PATH="$ENV:PATH;C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v$mmVersionTag\bin"
$ENV:CUDA_PATH="C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v$mmVersionTag"

$PATH_STR="PATH=$ENV:PATH"
$PATH_STR | Out-File -Append $ENV:GITHUB_ENV

$CUDA_PATH_STR="CUDA_PATH=$ENV:CUDA_PATH"
$CUDA_PATH_STR | Out-File -Append $ENV:GITHUB_ENV

Remove-Item .\cuda_network.exe
