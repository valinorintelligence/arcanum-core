# 📚 Arcanum Core — Registro de Aprendizados & Troubleshooting (Post-Mortem)

Este documento registra os diagnósticos técnicos, post-mortems de falhas resolvidas, regras de sustentação em ambiente Windows e diretrizes para auditorias autônomas com modelos locais.

---

## 1. Post-Mortem: Falha na Geração e Download de Relatórios

### Sintoma Observado
Ao executar uma auditoria (ex: sessão `leouve`) e tentar gerar relatórios pela interface web, o sistema apresentava erros, o botão ficava travado ou o download retornava `HTTP 404: No pdf report found`. No chat, o modelo emitia a string `generate_report` em texto puro.

### Causas Raízes (Root Cause Analysis)
1. **Dependência Externa Incompatível (WeasyPrint no Windows):**
   - O método `generate_pdf` importava `weasyprint`, que requer bibliotecas compiladas C/GTK (Cairo, Pango, GDK-PixBuf). No Windows, essa importação falhava silenciosamente.
   - O código antigo gravava um `.html` e retornava um caminho HTML, mas a rota de download buscava estritamente arquivos com extensão `*.pdf` (`glob("*.pdf")`), lançando exceção 404.
2. **Crash de Codificação de Caracteres (`cp1252`):**
   - A biblioteca padrão do Python no Windows adota a codificação ANSI/Windows-1252 se `encoding` não for declarado explicitamente em `Path.write_text()`. Textos em português com acentuação e emojis no sumário executivo geravam `UnicodeEncodeError`.
3. **Estado Inicial Vazio no Frontend:**
   - Em `frontend/index.html`, a propriedade `reportFormats` iniciava como `[]` (array vazio). As caixas de seleção começavam desmarcadas, desabilitando o botão de submissão.
4. **Alucinação do Modelo SLM 7B:**
   - Modelos quantizados menores (Qwen 7B) tendem a vocalizar a intenção de encerrar o ciclo emitindo o token `generate_report` como texto de resposta em vez de chamar uma ferramenta formal.

### Soluções Implementadas
- **Engine Headless Nativa com Microsoft Edge:**
  Implementada rotina que localiza `msedge.exe` (ou navegadores baseados em Chromium) e executa `--headless --disable-gpu --print-to-pdf=<output_pdf> <temp_html>`. Testado e validado: relatórios PDF vetoriais de 82KB gerados em menos de 1 segundo sem nenhuma dependência GTK.
- **Parametrização Explícita de UTF-8:**
  Adicionado `encoding="utf-8"` em todas as gravações de HTML, Markdown, JSON e PDF fallback em `arcanum/core/reports.py`.
- **Fallback Gracioso na API FastAPI:**
  Em `arcanum/api/routes/reports.py`, se a extensão solicitada for `pdf` e o arquivo não estiver disponível, o backend serve imediatamente o arquivo `*.html` com cabeçalho `media_type="text/html"`.
- **Reforço de UI no Frontend:**
  Formulário pré-carrega com `['html', 'pdf', 'md', 'json']`, vincula a sessão corrente automaticamente, exibe toasts em tempo real e chama `fetchReports()` logo após a geração.
- **Interceptador no Loop ReAct:**
  Em `arcanum/agent/engine.py`, qualquer saída contendo o token `generate_report` aciona o método interno `_generate_report()`, finalizando a operação com feedback claro em pt-BR.

---

## 2. Padrões de Comportamento para Modelos Locais Menores (7B/32B)

Quando operando em hardware com recursos contidos (CPU ou GPUs com 8GB a 16GB VRAM):
1. **Evitar Context Stuffing:** Não despejar saídas volumosas de scans no contexto do chat. O agente deve resumir dados brutos na Camada 2 (Episodic Wiki) em `workspace/wiki/TARGET_MAP.md`.
2. **Stagnation Guard:** Chamadas repetitivas à mesma ferramenta (ex: `audit_security_headers`) sem mudança de contexto indicam que o modelo local não conseguiu deduzir a transição de fase. O motor deve barrar a repetição e induzir o avanço.
3. **Roteamento de CDN/WAF:** Se cabeçalhos como `server: cloudflare` forem identificados na fase de reconhecimento, portas fechadas na borda não devem ser re-escaneadas; o foco deve migrar imediatamente para testes de cabeçalho, rotas de API pública e subdomínios.

---

## 3. Playbooks e Metodologia para Prospecção Comercial

Para transformar diagnósticos do Arcanum em auditorias vendáveis para donos de sistemas:
- **Alvos Recomendados:** Empresas de médio porte, e-commerces, portais de mídia/notícias e clínicas de saúde. Sistemas que processam dados pessoais (LGPD) mas não contam com equipe dedicada de segurança ofensiva.
- **WordPress — Vetor Não-Intrusivo:**
  - Enumeração de usuários via REST API pública (`/wp-json/wp/v2/users`) revela o login administrativo sem qualquer esforço de força bruta.
  - Ausência de `Content-Security-Policy` e `X-Frame-Options` permite demonstrar o risco de Clickjacking e injeção de iframes fraudulentos.
- **Estrutura de Pitch via WhatsApp:**
  1. *O Fato:* "Identifiquei que sua aplicação expõe os logins administrativos na API pública e não restringe enquadramento em outros domínios."
  2. *O Impacto:* "Criminosos podem clonar sua interface de pagamento via iframe ou direcionar ataques de credencial sabendo exatamente o usuário administrador."
  3. *A Solução:* "Gerei um relatório técnico preventivo com o plano de remediação e posso aplicar a correção em poucas horas."

---

## 4. Post-Mortem: Lentidão extrema da máquina (freeze → reboot)

### Sintoma
Durante o uso do Arcanum o laptop (Ryzen 7 4800H, **GTX 1650 4GB**, 64GB RAM) ficou muito lento,
exigindo reinicialização do PC.

### Causas-raízes (confirmadas por análise de logs)
Os logs do servidor **não** mostraram bug de runaway — sem tracebacks, **sem polling** no frontend
(os `/api/stats` eram navegação manual) e a reconexão WebSocket é limitada (3 tentativas → reload). A
lentidão é de **recursos**, não de um laço infinito:
1. **CPU saturada pelo modelo 7B.** O `qwen2.5-coder:7b` carrega ~**42% GPU / 58% CPU** (não cabe nos
   4GB de VRAM). Cada turno faz *prefill* na CPU, saturando os 8 núcleos por dezenas de segundos — o
   SO/UI ficam sem fôlego. Agravado por *prompts* grandes (ver BUG Perf; o system prompt foi reduzido
   de 6.951→~1.600 tokens, baixando o prefill de ~110s→~49s).
2. **Acúmulo de processos.** Reinícios do servidor deixaram processos `arcanum serve` órfãos presos à
   porta 8000 (comprovado por `Errno 10048` em `bklqr6l68.output`). Cada processo mantinha uma conexão
   Ollama e um loop do CTEM daemon.
3. **`keep_alive: -1`.** O cliente Ollama fixava o modelo na VRAM/RAM **para sempre** (~2.2GB VRAM +
   ~3.2GB RAM), mesmo ocioso.
4. **Docker Desktop (WSL2).** O `vmmem`/`vmmemWSL` do Docker é pesado no Windows mesmo sem containers.

### Correções e mitigações
- **Código:** `keep_alive` agora é configurável (`ARCANUM_OLLAMA_KEEP_ALIVE`, padrão **"30m"**) — libera
  VRAM/RAM quando o Arcanum fica ocioso. System prompt enxuto (já aplicado). Lock por sessão + abort de
  runs órfãos no disconnect (já aplicados).
- **Ambiente (aplicar e reiniciar o Ollama):**
  - `OLLAMA_FLASH_ATTENTION=1` e `OLLAMA_KV_CACHE_TYPE=q8_0` (metade da memória do KV cache; cabe mais
    contexto nos 4GB). **Confirmado ativo** no startup do llama-server: `--flash-attn on
    --cache-type-k q8_0 --cache-type-v q8_0`.
  - **Threads da CPU:** o env `OLLAMA_NUM_THREAD` é **ignorado** pelo Ollama (não repassa ao
    llama-server — verificado: `n_threads=8` mesmo com o env setado). O controle correto é a **opção
    por requisição** `num_thread`. **Agora é automático:** por padrão o Arcanum deixa ~2 núcleos
    físicos livres (`config.effective_num_thread()` → 6 de 8 nesta máquina), **sem precisar de env** —
    basta reiniciar o `arcanum serve`. Para ajustar: `ARCANUM_OLLAMA_NUM_THREAD=N` (N exato) ou `=-1`
    (usar todos os núcleos). Confirmado no llama-server: `-t 6` → `n_threads = 6`.
- **Operacional:**
  - Rodar **UM** `arcanum serve` por vez. Antes de reiniciar, matar o processo anterior na porta 8000
    (`Get-NetTCPConnection -LocalPort 8000` → `Stop-Process`).
  - Evitar **operações simultâneas** (duas sessões rodando o agente ao mesmo tempo saturam o Ollama;
    `OLLAMA_NUM_PARALLEL=1` serializa, mas o ideal é uma por vez neste hardware).
  - Ligar o **Docker Desktop apenas** quando for usar a ferramenta `execute` (recon real via Kali);
    as ~116 ferramentas `audit_*` nativas não precisam de Docker.
