# Binlex Windows Build Dependencies

$lief_url = "https://github.com/lief-project/LIEF/releases/download/0.11.5/LIEF-0.11.5-win64.zip";
$capstone_url = "https://github.com/capstone-engine/capstone/releases/download/4.0.2/capstone-4.0.2-win64.zip";

New-Item -ItemType Directory -Force -Path "build/sdks/"

Invoke-WebRequest -Uri $capstone_url -OutFile "build/sdks/capstone.zip"
Invoke-WebRequest -Uri $lief_url -OutFile "build/sdks/lief.zip"

Expand-Archive -Path "build/sdks/capstone.zip" -DestinationPath "build/sdks/capstone/"
Expand-Archive -Path "build/sdks/lief.zip" -DestinationPath "build/sdks/lief/"
