# PowerShell Script to Launch Local MongoDB Sharded Cluster Nodes
# Requires MongoDB Community Server installed locally.

$baseDir = Split-Path -Parent $PSScriptRoot
$dataRoot = Join-Path $baseDir "mongodb-data"

Write-Host "Creating data directories under $dataRoot..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path "$dataRoot\configdb" | Out-Null
New-Item -ItemType Directory -Force -Path "$dataRoot\shard1" | Out-Null
New-Item -ItemType Directory -Force -Path "$dataRoot\shard2" | Out-Null

Write-Host "Starting Config Server (port 27019)..." -ForegroundColor Yellow
Start-Process mongod -ArgumentList "--configsvr --replSet cfgReplSet --port 27019 --dbpath `"$dataRoot\configdb`" --bind_ip 127.0.0.1" -WindowStyle Minimized

Write-Host "Starting Shard 1 (port 27018)..." -ForegroundColor Yellow
Start-Process mongod -ArgumentList "--shardsvr --replSet shard1ReplSet --port 27018 --dbpath `"$dataRoot\shard1`" --bind_ip 127.0.0.1" -WindowStyle Minimized

Write-Host "Starting Shard 2 (port 27028)..." -ForegroundColor Yellow
Start-Process mongod -ArgumentList "--shardsvr --replSet shard2ReplSet --port 27028 --dbpath `"$dataRoot\shard2`" --bind_ip 127.0.0.1" -WindowStyle Minimized

Start-Sleep -Seconds 5

Write-Host "Starting mongos Query Router (port 27017)..." -ForegroundColor Green
Start-Process mongos -ArgumentList "--configdb cfgReplSet/127.0.0.1:27019 --port 27017 --bind_ip 127.0.0.1" -WindowStyle Minimized

Write-Host "`nAll 4 nodes launched successfully!" -ForegroundColor Green
Write-Host "Execute: mongosh --port 27017 < mongodb\scripts\init_sharding.js to initialize cluster." -ForegroundColor Cyan
