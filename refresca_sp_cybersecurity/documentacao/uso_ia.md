# IA aplicada à tradução e à remediação de riscos

## O papel da IA no Refresca SP

A proposta da disciplina pede **traduzir falhas técnicas em alertas claros de risco real para o cidadão** e inovar nas recomendações de remediação. Nesta versão, o ChatGPT foi utilizado **na elaboração dos textos**. Os textos ficam armazenados como templates no `analisador.py` e são escolhidos conforme a categoria identificada. **Não existe integração com LLM/API em tempo de execução**, preservando a independência entre matérias.

## Exemplo reproduzível de prompt

> Você é um assistente de segurança do projeto fictício Refresca SP. Uma auditoria local detectou registros de CPF, telefone, campos de saúde e senha em logs de uma aplicação de alertas SMS. Use **somente** os tipos de dados e as severidades; não peça nem processe nomes, documentos ou senhas reais. Para cada tipo, gere: (1) explicação em até duas frases que um cidadão idoso entenda, sem alarmismo; (2) recomendação técnica de prevenção, mencionando minimização, mascaramento ou bloqueio quando apropriado. Informe que a detecção é demonstrativa e não constitui comprovação de vazamento real.

O conteúdo do projeto foi elaborado e revisado sob essas diretrizes. Não é necessário executar esse prompt para rodar o módulo.

## Resultado adotado (exemplos)

| Achado | Tradução para o cidadão | Correção revisada |
|---|---|---|
| CPF | Seu documento pode ficar visível para pessoas com acesso aos registros técnicos. | Não registrar CPF completo; usar ID interno não sensível. |
| Telefone | Seu número de contato pode aparecer nos registros do envio de SMS. | Registrar ID da tentativa ou telefone mascarado. |
| Saúde | Informações particulares sobre saúde não devem aparecer em mensagens de diagnóstico. | Remover diagnósticos e restringir acesso aos dados necessários. |
| Senha | Uma senha exposta em registros pode facilitar acesso indevido à conta. | Bloquear a mensagem de log, nunca guardar senha legível e avaliar troca de credenciais afetadas. |

## Onde o resultado aparece

- `analisador.py`: dicionários de recomendações e função `remediacoes_por_tipo`.
- `saida/dashboard.html`: seção **Remediação traduzida com apoio de IA**.
- `saida/relatorio_auditoria.md`: seção de tradução e medidas de correção.

## Controles de qualidade

1. O parser disponibiliza ao gerador de relatórios **somente classes, níveis e valores mascarados**.
2. As frases não incluem nenhum CPF/telefone/senha/diagnóstico concreto.
3. As sugestões são **revisadas no código**, sem executar comandos sugeridos automaticamente por IA.
4. Não se promete que o filtro ou o motor regex garantam ausência de vazamentos reais.

O uso de IA aqui é **assistência à redação e interpretação**; não foi construído um modelo treinado, agente autônomo ou integração remota com serviço de IA.
