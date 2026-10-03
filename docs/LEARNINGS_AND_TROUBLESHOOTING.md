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
