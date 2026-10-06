# Arcanum Red Team - lab multi-host + engajamento (F1->F4->F5) runbook
# ---------------------------------------------------------------------------
# Rode a PARTIR da pasta do projeto (D:\Antigravity-Arkanum\arcanum-core):
#   powershell -ExecutionPolicy Bypass -File .\scripts\redteam_lab.ps1
#
# SEGURANCA: tudo e escopado a uma REDE DE LAB ISOLADA e a alvos que VOCE cria aqui
# (DVWA + um host SSH interno). NUNCA aponte para nada que voce nao seja dono.
# Os trilhos do Arcanum (ROE, HITL, audit, cleanup) seguem ativos.
#
# NOTA: este script NAO foi executado/validado por mim (a sessao bloqueou execucao);
# e best-effort. ASCII-only de proposito (PowerShell 5.1 le .ps1 como cp1252).
# ---------------------------------------------------------------------------

# EAP=Continue: comandos nativos (docker) que escrevem no stderr - ex. 'rm -f' de um
# container inexistente - NAO devem abortar o script. Erros reais via $LASTEXITCODE.
$ErrorActionPreference = "Continue"
$net     = "arcanum-lab"
$webPort = 8080

Write-Host "== 1. Docker engine ==" -ForegroundColor Cyan
docker context use default 2>$null | Out-Null
docker info 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERRO: Docker Desktop nao esta rodando (abra o Docker Desktop e aguarde o engine)." -ForegroundColor Red
    exit 1
}

Write-Host "== 2. Rede de lab isolada (arcanum-lab) ==" -ForegroundColor Cyan
if (-not (docker network ls --format '{{.Name}}' | Select-String -SimpleMatch $net)) {
    docker network create $net | Out-Null
}

Write-Host "== 3. Alvo de entrada web: DVWA (publicado em 127.0.0.1:8080) ==" -ForegroundColor Cyan
docker rm -f dvwa dvwa-db 2>$null | Out-Null
docker run -d --name dvwa --network $net -p "127.0.0.1:${webPort}:80" ghcr.io/digininja/dvwa:latest | Out-Null
docker run -d --name dvwa-db --network "container:dvwa" `
    -e MARIADB_ROOT_PASSWORD=rootpw -e MARIADB_DATABASE=dvwa `
    -e MARIADB_USER=dvwa -e "MARIADB_PASSWORD=p@ssw0rd" mariadb:11 | Out-Null
Write-Host ('   (no 1o acesso: Create/Reset Database em http://localhost:' + $webPort + '/setup.php; login admin/password; security low)')

Write-Host "== 4. Alvo interno p/ movimento lateral: host SSH (so na rede do lab) ==" -ForegroundColor Cyan
docker rm -f arcanum-internal 2>$null | Out-Null
docker run -d --name arcanum-internal --network $net `
    -e PUID=1000 -e PGID=1000 -e TZ=Etc/UTC `
    -e USER_NAME=svc -e USER_PASSWORD=Lab12345 -e PASSWORD_ACCESS=true `
    lscr.io/linuxserver/openssh-server:latest | Out-Null
Write-Host ('   alvo interno: host arcanum-internal [SSH svc/Lab12345] na rede ' + $net)

Write-Host "== 5. Imagem do sandbox Kali ==" -ForegroundColor Cyan
if (-not (docker images --format '{{.Repository}}' | Select-String -SimpleMatch 'arcanum-sandbox')) {
    arcanum sandbox build
}

Write-Host "== 6. Servidor Arcanum (em janela separada) ==" -ForegroundColor Cyan
$up = $false
try { $up = [bool](Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue) } catch {}
if ($up) {
    Write-Host "   ja ha um servidor na porta 8000 - usando o existente."
} else {
    Start-Process powershell -ArgumentList '-NoExit','-Command','$env:PYTHONIOENCODING=''utf-8''; arcanum serve'
    Start-Sleep -Seconds 8
}

# IMPORTANTE (rede do sandbox): o container do sandbox e criado pelo engine em runtime.
# Para alcancar o 'arcanum-internal' (que NAO e publicado no host), conecte o sandbox a
# rede do lab DEPOIS que ele existir (apos a 1a ferramenta 'execute' numa sessao):
#   docker network connect arcanum-lab <id-ou-nome-do-container-do-sandbox>
# O DVWA ja e alcancavel por host.docker.internal:8080 (porta publicada no host).

Write-Host "== 7. Engajamento full-scope de LAB (ROE) ==" -ForegroundColor Cyan
$t = (Get-Content $HOME\.arcanum\api_token.txt).Trim()
$body = @{
    name  = "multihost-lab"
    scope = @("host.docker.internal", "arcanum-internal", "dvwa")
} | ConvertTo-Json
$eng = Invoke-RestMethod -Method Post `
    -Uri "http://localhost:8000/api/redteam/engagements/lab-preset" `
    -Headers @{ Authorization = "Bearer $t" } -ContentType "application/json" -Body $body
Write-Host ("   engagement: " + $eng.engagement.id + "  auto_approve=" + $eng.engagement.auto_approve)

Write-Host ""
Write-Host "== LAB PRONTO ==" -ForegroundColor Green
Write-Host "Opere em http://localhost:8000 em AUTOPILOT, escopada ao lab:" -ForegroundColor Green
Write-Host ('  F1  recon/exploit web:   alvo http://host.docker.internal:' + $webPort + '  [DVWA, command injection]')
Write-Host '  F4  lateral p/ interno:  host arcanum-internal  [SSH svc/Lab12345] via o foothold'
Write-Host '  F5  PoC nao-destrutivo:  collect_sample [cap rigido]; impact_poc OFF salvo ARCANUM_ALLOW_DESTRUCTIVE_TESTING=1'
Write-Host ""
Write-Host "Evidencias e governanca (apos operar):"
Write-Host '  findings : http://localhost:8000/api/findings'
Write-Host '  audit    : http://localhost:8000/api/redteam/actions   decision=executed_preauthorized'
Write-Host '  verify   : http://localhost:8000/api/redteam/actions/verify   espera valid:true'
Write-Host '  footholds: http://localhost:8000/api/redteam/sessions'
Write-Host '  ENCERRAR : POST http://localhost:8000/api/redteam/killswitch   limpa footholds/implantes'

# Teardown do lab (quando terminar):
#   docker rm -f dvwa dvwa-db arcanum-internal
#   docker network rm arcanum-lab
