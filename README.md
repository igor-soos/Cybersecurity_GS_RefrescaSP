# Refresca SP — Cybersecurity | Global Solution 2026.2

> **CitizenTech: segurança dos dados do cidadão em alertas de calor extremo**  
> **Componente:** Motor de Parsing PII + Taint Analysis + Bloqueio preventivo + Dashboard Executivo  
> **Disciplina:** Cybersecurity — FIAP

## Equipe

Matheus - RM 555177

Gustavo Atanazio. - RM 559098

Nicolas - RM 556617

Gustavo Coelho -  RM 556289

Igor Soos - RM 556010


## 1. Problema e objetivo

O **Refresca SP** é uma proposta de serviço que avisa cidadãos, especialmente pessoas idosas e trabalhadores de rua, sobre calor extremo e pontos de hidratação/sombra. Um cadastro opcional para SMS poderia lidar com CPF, telefone e, em extensões futuras, outros dados privados. Logs de depuração **não devem expor essas informações**.

Esta entrega constrói um módulo isolado de auditoria capaz de reconhecer indícios de exposição de CPF, telefone, informações de saúde e senhas em logs fictícios; mapear fontes e destinos do dado no código; demonstrar o bloqueio de eventos inseguros antes da gravação; e apresentar remediações em linguagem acessível. Não existe integração real com o app, APIs, IoT ou IA em tempo de execução.

## 2. Como executar (Windows / VS Code)

**Requisitos:** Python **3.10+**; nenhuma biblioteca externa.

Abra no VS Code a pasta `refresca_sp_cybersecurity` e execute no terminal PowerShell:

```powershell
python --version
python analisador.py
python bloqueador.py
python -m unittest discover -s testes -v
Start-Process msedge.exe -ArgumentList (Resolve-Path ".\saida\dashboard.html").Path
```

Se o Windows não encontrar `python`, experimente `py`. O painel também abre com duplo clique em `saida/dashboard.html`.

Você pode apontar o auditor para outros arquivos **fictícios**:

```powershell
python analisador.py --log dados/log_simulado.txt --codigo dados/exemplo_fluxo.py --saida saida
```

**Importante:** não use logs reais nem credenciais reais para demonstrar esta solução acadêmica.

## 3. Estrutura

```text
refresca_sp_cybersecurity/
├── analisador.py                 # Regex PII + AST Taint + exportação
├── bloqueador.py                 # logging.Filter com descarte preventivo
├── modelo_dashboard.html         # Template do painel, sem dependências
├── dados/
│   ├── log_simulado.txt          # Logs artificiais com falhas intencionais
│   └── exemplo_fluxo.py          # Fluxo vulnerável e fluxo mascarado
├── testes/teste_auditoria.py     # 28 testes unittest
├── saida/
│   ├── dashboard.html            # Painel gerado
│   ├── relatorio_auditoria.md    # Relatório técnico/gerencial
│   ├── auditoria.json            # Resultados seguros estruturados
│   └── prova_bloqueio.txt        # Resumo do filtro de bloqueio
├── evidencias/                   # Capturas V2 e transcrições reais do terminal
├── documentacao/
│   ├── uso_ia.md                 # Tradução de risco e remediação
│   ├── roteiro_video.md          # Demonstração para entregar
│   └── criterios_avaliacao.md    # Alinhamento com os slides da FIAP
└── video/
    └── LEIA-ME.txt               # Local para incluir gravação final
```

## 4. Motor de Parsing PII (Regex)

O parser `analisar_linha()` percorre cada linha e gera **apenas metadados e valores mascarados**.

| Categoria | Exemplos de chave/formato reconhecido | Como aparece no relatório |
|---|---|---|
| CPF | `cpf=111.444.777-35`, `cpf=12345678909` | `***.***.***-35` |
| Telefone | `(11) 98888-7777`, `11987654321`, `+55 11 ...` | `(**) *****-7777` |
| Saúde | `diagnostico="valor simulado"`, `condicao_saude=valor`, JSON com `"saude"` | `[DADO DE SAÚDE OCULTO]` |
| Senha | `senha=valor`, `password=valor`, `passwd=valor`, `pwd=valor` | `[SEGREDO OCULTO]` |

O CPF usa cálculo de dígitos verificadores (ou contexto explícito `cpf=` para sinalizar um campo suspeito). Saúde e senhas exigem chaves reconhecidas. O parser tenta evitar confusão com `CEP`, temperaturas e campos já mascarados, mas pode errar.

A severidade acadêmica é **CRÍTICO** para senhas, **ALTO** para CPF/saúde e **MÉDIO** para telefone.

## 5. Taint Analysis (AST)

`analisar_codigo()` usa `ast` da biblioteca padrão do Python para detectar:

- **Source:** `payload['cpf']`, `payload['telefone']`, `payload['senha']`, `payload['saude']`.
- **Propagação:** atribuições e montagem de mensagens (`f-string`).
- **Sink:** `logger.info(...)`, outras chamadas `logger.*(...)` e `print(...)`.
- **Proteção reconhecida:** `mascarar_cpf`, `mascarar_telefone`, `ocultar_senha`, `ocultar_saude`, com tipo compatível.

No código fictício, o método `cadastrar_usuario_inseguro` produz **4 rastros vulneráveis** e `cadastrar_usuario_seguro` produz **4 rastros com proteção reconhecida**. Os rastros incluem as linhas do exemplo e são visíveis no dashboard. Essa técnica está restrita ao fluxo simples dentro de funções e não substitui um SAST completo.

## 6. Bloqueio preventivo, com execução real

`bloqueador.py` cria um `logging.Filter` para examinar a mensagem formatada **antes de o handler gravá-la**. Se o parser reconhecer PII, o filtro retorna `False` e a mensagem é descartada daquele destino. O teste contém 6 tentativas fictícias: **4 bloqueadas** e **2 permitidas**.

O bloqueador não apaga logs antigos, não intercepta outros handlers nem garante a detecção de todas as formas de dados sensíveis. Esse recorte é intencional e está explicado no relatório.

## 7. Dashboard Executivo — Indicador Risco Cidadão

O HTML gerado exibe:

- Contagem de cada tipo de PII, achados mascarados e severidade.
- **Risco Cidadão**, índice demonstrativo de 0 a 100.
- Caminhos identificados pela Taint Analysis.
- Quantidade de mensagens preventivamente bloqueadas.
- Remediações técnicas e traduções para o cidadão elaboradas com apoio do ChatGPT.

O índice soma pesos por ocorrências (**CPF 6, Telefone 3, Saúde 10, Senha 16**, até 3 por tipo) mais **3 por fluxo vulnerável** (até 5), limitado a 100. **É uma convenção didática criada para o projeto, não uma pontuação reconhecida de risco real ou de conformidade com a LGPD.**

## 8. IA na remediação

Durante a **elaboração** do projeto, o ChatGPT auxiliou na tradução dos achados técnicos para mensagens simples e sugestões de correção por tipo de vulnerabilidade. O programa utiliza esses textos **já revisados e armazenados localmente**, sem chamada ao ChatGPT/Gemini durante sua execução. Só foram considerados cenários fictícios e categorias de risco, sem dados pessoais reais. Consulte [`documentacao/uso_ia.md`](documentacao/uso_ia.md) para o fluxo reproduzível e exemplos de conteúdo.

## 9. Resultados da amostra v2

| Métrica | Resultado |
|---|---:|
| Linhas de log | 14 |
| Possíveis exposições | 11 |
| CPF / Telefone / Saúde / Senha | 3 / 4 / 2 / 2 |
| Rastros vulneráveis / com proteção | 4 / 4 |
| Tentativas bloqueadas / testadas | 4 / 6 |
| Índice Risco Cidadão | 91/100 (didático) |
| Severidade geral | CRÍTICO |
| Testes automatizados | **28 aprovados** |

O valor **CRÍTICO** descreve as falhas **inseridas propositalmente na amostra**; não significa que o auditor em si falhou.

## 10. Link do vídeo

- 

## 11. Limitações e recomendações

- Trata-se de uma **prova de conceito acadêmica**, com dados totalmente artificiais.
- Regex reconhece alguns formatos/chaves; há possibilidade de falsos positivos e negativos.
- O rastreador AST avalia somente um subconjunto de construções Python e **não confirma a eficácia real da implementação de todo sanitizador**.
- O bloqueio protege **somente o handler onde o filtro foi instalado**.
- Nunca use senhas, documentos ou dados médicos de pessoas reais para testar o protótipo.
- Em um ambiente real, recomenda-se minimizar coleta/retensão de PII, revisar acessos, estabelecer política de logs e aplicar proteção em todos os destinos.
- Este exercício não comprova conformidade com a LGPD nem substitui auditoria profissional.
