# Refresca SP — Relatório de Auditoria de Cybersecurity (v2)

## Objetivo
Avaliar exposição de dados de cadastro para alertas SMS do Refresca SP, com detecção contextual de PII, Taint Analysis didática, demonstração de bloqueio de logs inseguros e remediações redigidas com apoio de IA.

## Escopo e método
- Projeto **isolado** (Python puro). Todos os dados são fictícios; sem integração com APIs e sem chamadas a serviços de IA.
- **Parsing PII:** regex e validação contextual para CPF, telefone, campos de saúde e credenciais.
- **Taint Analysis:** análise AST intrafunção; fontes `payload[...]`, propagação por variáveis e destinos de logging.
- **Bloqueio dinâmico:** `logging.Filter` impede escrita de mensagens que contenham PII reconhecida.
- **Remediação com IA:** textos criados com auxílio do ChatGPT durante a elaboração e revisados para serem usados como templates locais.

## Indicadores
- Linhas verificadas: **14**.
- Ocorrências identificadas: **11**.
- CPF: **3**.
- Telefone: **4**.
- Saúde: **2**.
- Senha: **2**.
- Fluxos vulneráveis: **4**.
- Fluxos protegidos: **4**.
- Índice didático Risco Cidadão: **91/100**; classificação: **CRÍTICO**.
- Índice calculado pela soma dos pesos CPF=6, Telefone=3, Saúde=10 e Senha=16 (até três ocorrências por tipo), mais 3 por fluxo inseguro (até cinco), limitado a 100. **Não é uma métrica oficial nem avalia risco real.**

## Achados nos logs (valores mascarados)
| Linha | Tipo | Risco | Evidência protegida |
|---:|---|---|---|
| 3 | CPF | ALTO | `***.***.***-35` |
| 3 | Telefone | MÉDIO | `(**) *****-7777` |
| 4 | CPF | ALTO | `***.***.***-09` |
| 4 | Telefone | MÉDIO | `(**) *****-4321` |
| 5 | Telefone | MÉDIO | `(**) *****-6666` |
| 7 | CPF | ALTO | `***.***.***-00` |
| 7 | Telefone | MÉDIO | `(**) *****-7890` |
| 9 | Saúde | ALTO | `[DADO DE SAÚDE OCULTO]` |
| 10 | Saúde | ALTO | `[DADO DE SAÚDE OCULTO]` |
| 11 | Senha | CRÍTICO | `[SEGREDO OCULTO]` |
| 12 | Senha | CRÍTICO | `[SEGREDO OCULTO]` |

## Taint Analysis — caminho dos dados

- **VULNERÁVEL — CPF** (`cadastrar_usuario_inseguro`, L31): Entrada: payload['cpf'] (L26) → Variável: cpf (L26) → Variável: mensagem (L30) → Destino: logger.info() (L31)
- **VULNERÁVEL — Telefone** (`cadastrar_usuario_inseguro`, L31): Entrada: payload['telefone'] (L27) → Variável: telefone (L27) → Variável: mensagem (L30) → Destino: logger.info() (L31)
- **VULNERÁVEL — Senha** (`cadastrar_usuario_inseguro`, L31): Entrada: payload['senha'] (L28) → Variável: senha (L28) → Variável: mensagem (L30) → Destino: logger.info() (L31)
- **VULNERÁVEL — Saúde** (`cadastrar_usuario_inseguro`, L31): Entrada: payload['saude'] (L29) → Variável: saude (L29) → Variável: mensagem (L30) → Destino: logger.info() (L31)
- **PROTEGIDO — CPF** (`cadastrar_usuario_seguro`, L39): Entrada: payload['cpf'] (L35) → Variável: cpf (L35) → Proteção: mascarar_cpf() (L40) → Destino: logger.info() (L39)
- **PROTEGIDO — Telefone** (`cadastrar_usuario_seguro`, L39): Entrada: payload['telefone'] (L36) → Variável: telefone (L36) → Proteção: mascarar_telefone() (L40) → Destino: logger.info() (L39)
- **PROTEGIDO — Senha** (`cadastrar_usuario_seguro`, L39): Entrada: payload['senha'] (L37) → Variável: senha (L37) → Proteção: ocultar_senha() (L41) → Destino: logger.info() (L39)
- **PROTEGIDO — Saúde** (`cadastrar_usuario_seguro`, L39): Entrada: payload['saude'] (L38) → Variável: saude (L38) → Proteção: ocultar_saude() (L41) → Destino: logger.info() (L39)

## Demonstração de bloqueio preventivo
- Mensagens de teste: **6**.
- Mensagens bloqueadas pelo filtro: **4**.
- Mensagens permitidas: **2**.
- O filtro evita a escrita no **handler demonstrativo**. Não remove conteúdo de arquivos antigos, não cobre todos os formatos e não substitui controles aplicados aos demais destinos de log.

## Tradução para o cidadão — texto com apoio de IA
Foram encontrados indícios de exposição de dados pessoais e de credenciais em registros simulados. Se uma senha aparecer em logs reais, ela pode permitir acesso indevido às contas. A prioridade é interromper o registro de segredos, restringir acesso aos logs e revisar credenciais afetadas.

## Remediações por vulnerabilidade

### Senha — Segredos em registros técnicos
- **Para o cidadão:** Uma senha registrada pode dar a terceiros acesso à conta do cidadão.
- **Correção recomendada:** Bloquear o log contendo credenciais, remover o dado do evento e avaliar rotação de senhas expostas.

### Saúde — Privacidade de dados de saúde
- **Para o cidadão:** Informações de saúde são privadas e não devem constar em mensagens de diagnóstico.
- **Correção recomendada:** Não registrar diagnósticos, sintomas ou medicação; usar códigos técnicos e limitar acessos.

### CPF — Exposição de documento
- **Para o cidadão:** O documento de identificação pode ser visto por quem tenha acesso aos registros.
- **Correção recomendada:** Eliminar o CPF do log; se estritamente necessário, substituí-lo por identificador opaco.

### Telefone — Exposição do contato
- **Para o cidadão:** O número de contato do cidadão pode ficar visível nos registros.
- **Correção recomendada:** Registrar apenas o identificador da tentativa de SMS ou uma versão mascarada do telefone.

## Evidências para o vídeo e a entrega
- `evidencias/01_dashboard_v2.png`: dashboard com índice Risco Cidadão.
- `evidencias/02_taint_v2.png`: rastros seguros e inseguros no HTML.
- `evidencias/03_execucao.txt`: saída real do analisador no terminal.
- `evidencias/04_testes.txt`: saída real dos testes automatizados.
- `evidencias/05_bloqueio.txt`: saída do filtro preventivo.
- `evidencias/06_remediacao_v2.png`: painel com remediações assistidas por IA.
- `evidencias/07_bloqueio_v2.png`: painel com a demonstração de bloqueio.
- Para o vídeo, gravar o projeto **rodando no VS Code e no navegador**.

## IA na elaboração (sem envio de PII)
Os textos de impacto e remediação foram elaborados com auxílio do ChatGPT usando somente nomes de categorias e cenários **fictícios**, sem upload de logs reais. Ver `documentacao/uso_ia.md`.

## Limitações e segurança
- A análise AST não avalia fluxos entre funções, condicionais complexas, aliases nem a implementação real de todos os sanitizadores.
- O motor regex pode produzir falsos positivos e falsos negativos; somente certos formatos e chaves são reconhecidos.
- A análise não elimina vazamentos já existentes e a demonstração não equivale a proteção integral de produção.
- Não armazenar nem submeter dados pessoais reais neste exercício.
- O índice do dashboard é apenas didático. O projeto não certifica aderência à LGPD.
