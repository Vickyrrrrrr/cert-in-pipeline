# cert-in-pipeline — one-line install (Windows)
#   iwr -useb https://vxky.me/cert-in-pipeline/install.ps1 | iex
$script = Invoke-RestMethod "https://raw.githubusercontent.com/Vickyrrrrrr/cert-in-pipeline/main/scripts/install.ps1"
Invoke-Expression $script
