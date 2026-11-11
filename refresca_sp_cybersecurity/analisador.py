"""Refresca SP — auditoria local demonstrativa de PII e fluxos de dados.

Executa somente na máquina local, sem bibliotecas externas nem APIs.
Os relatórios não reproduzem os valores sensíveis encontrados nos logs.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import html
import json
from pathlib import Path
import re

BASE = Path(__file__).resolve().parent

CPF_RE = re.compile(r"(?<!\d)(?:\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})(?!\d)")
TELEFONE_RE = re.compile(
    r"(?<!\d)(?:(?:\+55|55)[\s.-]?)?(?:\(?[1-9]\d\)?[\s.-]?)?"
    r"(?:9\d{4}|[2-8]\d{3})[\s.-]?\d{4}(?!\d)"
)
CPF_CONTEXT_RE = re.compile(r"\bcpf\b\s*[=:]\s*[\"']?\s*$", re.IGNORECASE)
PHONE_CONTEXT_RE = re.compile(r"\b(?:telefone|celular|phone|fone)\b\s*[=:]\s*[\"']?\s*$", re.IGNORECASE)
# Regra contextual: campos nomeados, não palavras soltas no texto do log.
CAMPO_RE = re.compile(
    r'''(?<![\w])(?P<abre>["']?)(?P<chave>senha|password|passwd|pwd|diagnostico|diagnóstico|condicao_saude|condição_saúde|saude|saúde|medicacao|medicação|sintomas)(?P=abre)\s*[:=]\s*(?P<valor>"[^"\r\n]{1,120}"|'[^'\r\n]{1,120}'|[^\s,;}]{1,120})''',
    flags=re.IGNORECASE,
)
TIPOS_CAMPOS = {
    'senha': 'Senha', 'password': 'Senha', 'passwd': 'Senha', 'pwd': 'Senha',
    'diagnostico': 'Saúde', 'diagnóstico': 'Saúde', 'condicao_saude': 'Saúde',
    'condição_saúde': 'Saúde', 'saude': 'Saúde', 'saúde': 'Saúde',
    'medicacao': 'Saúde', 'medicação': 'Saúde', 'sintomas': 'Saúde',
}
SENSITIVE_KEYS = {
    'cpf': 'CPF', 'telefone': 'Telefone', 'celular': 'Telefone',
    'phone': 'Telefone', 'fone': 'Telefone', **TIPOS_CAMPOS,
}
NIVEIS = {'CPF': 'ALTO', 'Telefone': 'MÉDIO', 'Saúde': 'ALTO', 'Senha': 'CRÍTICO'}
RECOMENDACOES = {
    'CPF': 'Evitar registrar CPF; se necessário, usar um identificador interno ou mascaramento.',
    'Telefone': 'Usar ID interno para eventos de SMS ou ocultar o número antes do log.',
    'Saúde': 'Remover informações de saúde dos logs e restringir acesso aos sistemas que as tratam.',
    'Senha': 'Nunca registrar senhas ou segredos; bloquear o evento antes da gravação.',
}
MOTIVOS = {
    'CPF': 'Documento de identificação encontrado em log de aplicação.',
    'Telefone': 'Contato do cidadão encontrado em log de aplicação.',
    'Saúde': 'Campo de saúde detectado com conteúdo legível em log.',
    'Senha': 'Campo de senha ou segredo detectado com conteúdo legível em log.',
}
# Sanitizadores aceitos apenas para o tipo correto; ainda requerem revisão humana.
SANITIZERS = {
    'mascarar_cpf': {'CPF'}, 'mascarar_telefone': {'Telefone'},
    'ocultar_saude': {'Saúde'}, 'ocultar_senha': {'Senha'},
    'sanitizar_pii': {'CPF', 'Telefone', 'Saúde', 'Senha'},
}
SINK_METHODS = {'debug', 'info', 'warning', 'warn', 'error', 'critical', 'exception', 'log'}


def somente_digitos(value: str) -> str:
    return ''.join(c for c in value if c.isdigit())


def cpf_valido(value: str) -> bool:
    digitos = somente_digitos(value)
    if len(digitos) != 11 or len(set(digitos)) == 1:
        return False
    for qt in (9, 10):
        dv = (sum(int(digitos[i]) * (qt + 1 - i) for i in range(qt)) * 10) % 11
        if (0 if dv == 10 else dv) != int(digitos[qt]):
            return False
    return True


def mascara(tipo: str, valor: str) -> str:
    digitos = somente_digitos(valor)
    if tipo == 'CPF':
        return f'***.***.***-{digitos[-2:]}'
    if tipo == 'Telefone':
        return f'(**) *****-{digitos[-4:]}'
    if tipo == 'Senha':
        return '[SEGREDO OCULTO]'
    if tipo == 'Saúde':
        return '[DADO DE SAÚDE OCULTO]'
    return '[OCULTO]'


def foi_mascarado(valor: str) -> bool:
    valor = valor.strip().strip('"\'').strip().upper()
    return (not valor or valor in {'-', 'NULL', 'NONE', 'N/A', '[OCULTO]', '[REDACTED]',
                                   '[REMOVIDO]', '[MASCARADO]', 'MASCARADO', 'REDACTED',
                                   '********', '******', 'XXXXX', '[SEGREDO OCULTO]',
                                   '[DADO DE SAÚDE OCULTO]'} or
            (len(valor) >= 3 and set(valor) <= {'*', 'X'}))


def sobreposicao(span: tuple[int, int], outros: list[tuple[int, int]]) -> bool:
    return any(span[0] < fim and ini < span[1] for ini, fim in outros)


def contexto_antes(texto: str, inicio: int) -> str:
    return texto[max(inicio - 30, 0):inicio]


def achado(linha: int, tipo: str, valor: str) -> dict:
    return {
        'linha': linha, 'tipo': tipo, 'nivel': NIVEIS[tipo],
        'evidencia': mascara(tipo, valor), 'motivo': MOTIVOS[tipo],
        'recomendacao': RECOMENDACOES[tipo],
    }


def analisar_linha(line: str, num_linha: int) -> list[dict]:
    """Inspeciona uma linha e devolve APENAS metadados seguros para relatório."""
    resultados: list[dict] = []
    cobertos: list[tuple[int, int]] = []
    # Saúde e senha têm precedência para não confundir números no conteúdo desses campos.
    for match in CAMPO_RE.finditer(line):
        valor = match.group('valor')
        if foi_mascarado(valor):
            continue
        tipo = TIPOS_CAMPOS[match.group('chave').lower()]
        resultados.append(achado(num_linha, tipo, valor))
        cobertos.append(match.span('valor'))

    for match in CPF_RE.finditer(line):
        if sobreposicao(match.span(), cobertos):
            continue
        anterior = contexto_antes(line, match.start())
        contexto_cpf = bool(CPF_CONTEXT_RE.search(anterior))
        contexto_telefone = bool(PHONE_CONTEXT_RE.search(anterior))
        if contexto_telefone and not contexto_cpf:
            continue
        if not cpf_valido(match.group()) and not contexto_cpf:
            continue
        resultados.append(achado(num_linha, 'CPF', match.group()))
        cobertos.append(match.span())

    for match in TELEFONE_RE.finditer(line):
        if sobreposicao(match.span(), cobertos):
            continue
        anterior = contexto_antes(line, match.start())
        digitos = somente_digitos(match.group())
        estruturado = bool(re.search(r'[()+\s.-]', match.group()))
        contexto_telefone = bool(PHONE_CONTEXT_RE.search(anterior))
        if len(digitos) == 11 and cpf_valido(match.group()) and not contexto_telefone:
            continue
        if len(digitos) == 8 and not contexto_telefone and not estruturado:
            continue
        resultados.append(achado(num_linha, 'Telefone', match.group()))
    ordem = {'CPF': 0, 'Telefone': 1, 'Saúde': 2, 'Senha': 3}
    return sorted(resultados, key=lambda x: ordem[x['tipo']])


def analisar_log(path: Path) -> tuple[int, list[dict]]:
    linhas = path.read_text(encoding='utf-8').splitlines()
    return len(linhas), [x for numero, linha in enumerate(linhas, 1) for x in analisar_linha(linha, numero)]


@dataclass(frozen=True)
class Fluxo:
    tipo: str
    origem: str
    etapas: tuple[str, ...]
    sanitizado: bool = False


def avaliar_expr(node: ast.AST, ambiente: dict[str, list[Fluxo]]) -> list[Fluxo]:
    if isinstance(node, ast.Name):
        return list(ambiente.get(node.id, []))
    if isinstance(node, ast.Subscript):
        chave = node.slice.value if isinstance(node.slice, ast.Constant) else None
        if isinstance(node.value, ast.Name) and node.value.id in {'payload', 'dados', 'request_data'}:
            if isinstance(chave, str) and chave.lower() in SENSITIVE_KEYS:
                tipo = SENSITIVE_KEYS[chave.lower()]
                desc = f"{node.value.id}['{chave}']"
                return [Fluxo(tipo, desc, (f'Entrada: {desc} (L{node.lineno})',))]
        return avaliar_expr(node.value, ambiente)
    if isinstance(node, ast.Call):
        fluxos = [f for arg in node.args for f in avaliar_expr(arg, ambiente)]
        fluxos.extend(f for kw in node.keywords for f in avaliar_expr(kw.value, ambiente))
        # Não aceitar objeto.arbitrario como sanitizador; apenas funções confiadas nominalmente.
        if isinstance(node.func, ast.Name) and node.func.id in SANITIZERS:
            nome = node.func.id
            return [replace(f, sanitizado=True,
                            etapas=f.etapas + (f'Proteção: {nome}() (L{node.lineno})',))
                    if f.tipo in SANITIZERS[nome] else f for f in fluxos]
        return fluxos
    if isinstance(node, ast.JoinedStr):
        return [f for parte in node.values for f in avaliar_expr(parte, ambiente)]
    if isinstance(node, ast.FormattedValue):
        return avaliar_expr(node.value, ambiente)
    if isinstance(node, ast.BinOp):
        return avaliar_expr(node.left, ambiente) + avaliar_expr(node.right, ambiente)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return [f for item in node.elts for f in avaliar_expr(item, ambiente)]
    if isinstance(node, ast.Dict):
        return [f for valor in node.values if valor is not None for f in avaliar_expr(valor, ambiente)]
    if isinstance(node, ast.IfExp):
        return avaliar_expr(node.body, ambiente) + avaliar_expr(node.orelse, ambiente)
    return []


def is_log_sink(call: ast.Call) -> bool:
    if isinstance(call.func, ast.Name) and call.func.id == 'print':
        return True
    if isinstance(call.func, ast.Attribute) and call.func.attr in SINK_METHODS:
        return isinstance(call.func.value, ast.Name) and call.func.value.id in {'logger', 'logging', 'log'}
    return False


def analisar_codigo(path: Path) -> list[dict]:
    """Taint Analysis estática intrafunção. Não cobre estruturas arbitrárias."""
    arvore = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    resultado: list[dict] = []
    for func in (n for n in arvore.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        ambiente: dict[str, list[Fluxo]] = {}
        for instrucao in func.body:
            if isinstance(instrucao, (ast.Assign, ast.AnnAssign)):
                if instrucao.value is None:
                    continue
                fluxos = avaliar_expr(instrucao.value, ambiente)
                alvos = instrucao.targets if isinstance(instrucao, ast.Assign) else [instrucao.target]
                for alvo in alvos:
                    if isinstance(alvo, ast.Name):
                        ambiente[alvo.id] = [replace(f, etapas=f.etapas +
                                                    (f'Variável: {alvo.id} (L{instrucao.lineno})',))
                                            for f in fluxos]
            if isinstance(instrucao, ast.Expr) and isinstance(instrucao.value, ast.Call) and is_log_sink(instrucao.value):
                call = instrucao.value
                fluxos = [f for arg in call.args for f in avaliar_expr(arg, ambiente)]
                fluxos.extend(f for kw in call.keywords for f in avaliar_expr(kw.value, ambiente))
                for fluxo in fluxos:
                    status = 'PROTEGIDO' if fluxo.sanitizado else 'VULNERÁVEL'
                    destino = f'{ast.unparse(call.func)}() (L{call.lineno})'
                    resultado.append({
                        'funcao': func.name, 'tipo': fluxo.tipo, 'origem': fluxo.origem,
                        'destino': destino, 'linha': call.lineno, 'status': status,
                        'nivel': 'BAIXO' if fluxo.sanitizado else NIVEIS[fluxo.tipo],
                        'rastro': list(fluxo.etapas) + [f'Destino: {destino}'],
                    })
    return resultado


def calcular_risco(ocorrencias: list[dict], fluxos: list[dict]) -> str:
    inseguros = [f for f in fluxos if f['status'] == 'VULNERÁVEL']
    niveis = {x['nivel'] for x in ocorrencias + inseguros}
    for nivel in ('CRÍTICO', 'ALTO', 'MÉDIO'):
        if nivel in niveis:
            return nivel
    return 'BAIXO'


def calcular_indice_cidadao(ocorrencias: list[dict], fluxos: list[dict]) -> int:
    """Índice didático 0–100; não mede risco real nem conformidade legal."""
    quantidades = Counter(x['tipo'] for x in ocorrencias)
    pesos = {'CPF': 6, 'Telefone': 3, 'Saúde': 10, 'Senha': 16}
    exposicao = sum(min(quantidades[tipo], 3) * peso for tipo, peso in pesos.items())
    caminhos = min(sum(f['status'] == 'VULNERÁVEL' for f in fluxos), 5) * 3
    return min(100, exposicao + caminhos)


def explicar_risco(risco: str, contagens: Counter | None = None) -> str:
    contagens = contagens or Counter()
    if risco == 'CRÍTICO':
        return ('Foram encontrados indícios de exposição de dados pessoais e de credenciais em registros simulados. '
                'Se uma senha aparecer em logs reais, ela pode permitir acesso indevido às contas. '
                'A prioridade é interromper o registro de segredos, restringir acesso aos logs e revisar credenciais afetadas.')
    if risco == 'ALTO':
        return ('Informações pessoais como CPF ou dados de saúde podem ficar disponíveis em registros técnicos. '
                'Esses dados não são necessários para investigar a maioria dos problemas e devem ser removidos ou ocultados.')
    if risco == 'MÉDIO':
        return ('Foram detectados contatos pessoais em logs simulados. O cidadão pode ter sua privacidade afetada '
                'se esses registros forem acessados por pessoas não autorizadas.')
    return ('As regras configuradas não encontraram exposição na amostra. Isso não prova ausência de vulnerabilidades: '
            'formatos novos e caminhos não analisados ainda podem causar vazamentos.')


def remediacoes_por_tipo(ocorrencias: list[dict], fluxos: list[dict]) -> list[dict]:
    """Textos revisados com auxílio de IA na elaboração; execução totalmente offline."""
    conteudo = {
        'Senha': ('Segredos em registros técnicos',
                  'Uma senha registrada pode dar a terceiros acesso à conta do cidadão.',
                  'Bloquear o log contendo credenciais, remover o dado do evento e avaliar rotação de senhas expostas.'),
        'Saúde': ('Privacidade de dados de saúde',
                  'Informações de saúde são privadas e não devem constar em mensagens de diagnóstico.',
                  'Não registrar diagnósticos, sintomas ou medicação; usar códigos técnicos e limitar acessos.'),
        'CPF': ('Exposição de documento',
                'O documento de identificação pode ser visto por quem tenha acesso aos registros.',
                'Eliminar o CPF do log; se estritamente necessário, substituí-lo por identificador opaco.'),
        'Telefone': ('Exposição do contato',
                     'O número de contato do cidadão pode ficar visível nos registros.',
                     'Registrar apenas o identificador da tentativa de SMS ou uma versão mascarada do telefone.'),
    }
    tipos = {item['tipo'] for item in ocorrencias + [f for f in fluxos if f['status'] == 'VULNERÁVEL']}
    return [{'tipo': tipo, 'titulo': conteudo[tipo][0],
             'linguagem_cidadao': conteudo[tipo][1], 'acao_tecnica': conteudo[tipo][2]}
            for tipo in ('Senha', 'Saúde', 'CPF', 'Telefone') if tipo in tipos]


def escapar(valor: object) -> str:
    return html.escape(str(valor), quote=True)


def criar_dashboard(relatorio: dict) -> str:
    ocorrencias = relatorio['ocorrencias']
    fluxos = relatorio['fluxos']
    contagens = Counter(x['tipo'] for x in ocorrencias)
    riscos = {'CRÍTICO': 'critico', 'ALTO': 'alto', 'MÉDIO': 'medio', 'BAIXO': 'baixo'}
    cores = {'CPF': 'cpf', 'Telefone': 'telefone', 'Saúde': 'saude', 'Senha': 'senha'}
    pico = max(contagens.values(), default=1)
    cards = ''.join(
        f'<div class="stat"><span>{escapar(tipo)} detectados</span>'
        f'<strong class="number {cores[tipo]}">{contagens[tipo]}</strong>'
        f'<small>ocorrências nos logs</small></div>' for tipo in ('CPF', 'Telefone', 'Saúde', 'Senha')
    )
    barras = ''.join(
        f'<div class="barrow"><b>{escapar(tipo)}</b><div class="barbg">'
        f'<div class="bar {cores[tipo]}" style="width:{round(contagens[tipo]/pico*100)}%"></div>'
        f'</div><b>{contagens[tipo]}</b></div>' for tipo in ('CPF', 'Telefone', 'Saúde', 'Senha')
    )
    tabela = ''.join(
        f'<tr><td>{x["linha"]}</td><td>{escapar(x["tipo"])}</td>'
        f'<td><span class="tag {riscos[x["nivel"]]}">{escapar(x["nivel"])}</span></td>'
        f'<td><code>{escapar(x["evidencia"])}</code></td><td>{escapar(x["recomendacao"])}</td></tr>'
        for x in ocorrencias
    ) or '<tr><td colspan="5">Nenhuma ocorrência identificada.</td></tr>'
    rastros = ''.join(
        f'<tr><td>{escapar(f["funcao"])}</td><td>{escapar(f["tipo"])}</td>'
        f'<td><span class="tag {"protegido" if f["status"] == "PROTEGIDO" else "alto"}">'
        f'{escapar(f["status"])}</span></td>'
        f'<td class="rastro">{ " <span class=\'seta\'>→</span> ".join(escapar(p) for p in f["rastro"]) }</td></tr>'
        for f in fluxos
    ) or '<tr><td colspan="4">Nenhum fluxo identificado.</td></tr>'
    remedios = ''.join(
        f'<div class="remedio"><div class="remedio-label">{escapar(r["tipo"])}</div>'
        f'<h3>{escapar(r["titulo"])}</h3><p><b>Para o cidadão:</b> {escapar(r["linguagem_cidadao"])}</p>'
        f'<p><b>Ação técnica:</b> {escapar(r["acao_tecnica"])}</p></div>'
        for r in relatorio['remediacoes']
    ) or '<p>Nenhuma remediação específica sugerida para a amostra.</p>'
    bloqueio = relatorio['bloqueio']
    protegidos = sum(f['status'] == 'PROTEGIDO' for f in fluxos)
    vulneraveis = sum(f['status'] == 'VULNERÁVEL' for f in fluxos)
    data = {
        'CARDS': cards, 'BARRAS': barras, 'TABELA': tabela, 'RASTROS': rastros,
        'REMEDIOS': remedios, 'RISCO': escapar(relatorio['risco_geral']),
        'RISCO_CSS': riscos[relatorio['risco_geral']], 'INDICE': str(relatorio['indice_cidadao']),
        'TOTAL': str(len(ocorrencias)), 'LINHAS': str(relatorio['linhas_analisadas']),
        'FLUXOS_VULNERAVEIS': str(vulneraveis), 'FLUXOS_PROTEGIDOS': str(protegidos),
        'TENTATIVAS': str(bloqueio['tentativas']), 'BLOQUEADOS': str(bloqueio['bloqueados']),
        'PERMITIDOS': str(bloqueio['permitidos']),
        'EXPLICACAO': escapar(relatorio['explicacao_simples']),
        'GERADO': escapar(relatorio['gerado_em_utc']),
    }
    template = (BASE / 'modelo_dashboard.html').read_text(encoding='utf-8')
    for chave, valor in data.items():
        template = template.replace('{{' + chave + '}}', valor)
    return template


def criar_relatorio_md(relatorio: dict) -> str:
    contagens = Counter(x['tipo'] for x in relatorio['ocorrencias'])
    linhas = [
        '# Refresca SP — Relatório de Auditoria de Cybersecurity (v2)', '',
        '## Objetivo',
        'Avaliar exposição de dados de cadastro para alertas SMS do Refresca SP, com detecção contextual de PII, '
        'Taint Analysis didática, demonstração de bloqueio de logs inseguros e remediações redigidas com apoio de IA.', '',
        '## Escopo e método',
        '- Projeto **isolado** (Python puro). Todos os dados são fictícios; sem integração com APIs e sem chamadas a serviços de IA.',
        '- **Parsing PII:** regex e validação contextual para CPF, telefone, campos de saúde e credenciais.',
        '- **Taint Analysis:** análise AST intrafunção; fontes `payload[...]`, propagação por variáveis e destinos de logging.',
        '- **Bloqueio dinâmico:** `logging.Filter` impede escrita de mensagens que contenham PII reconhecida.',
        '- **Remediação com IA:** textos criados com auxílio do ChatGPT durante a elaboração e revisados para serem usados como templates locais.', '',
        '## Indicadores',
        f'- Linhas verificadas: **{relatorio["linhas_analisadas"]}**.',
        f'- Ocorrências identificadas: **{len(relatorio["ocorrencias"])}**.',
        *[f'- {tipo}: **{contagens[tipo]}**.' for tipo in ('CPF', 'Telefone', 'Saúde', 'Senha')],
        f'- Fluxos vulneráveis: **{sum(f["status"] == "VULNERÁVEL" for f in relatorio["fluxos"])}**.',
        f'- Fluxos protegidos: **{sum(f["status"] == "PROTEGIDO" for f in relatorio["fluxos"])}**.',
        f'- Índice didático Risco Cidadão: **{relatorio["indice_cidadao"]}/100**; classificação: **{relatorio["risco_geral"]}**.',
        '- Índice calculado pela soma dos pesos CPF=6, Telefone=3, Saúde=10 e Senha=16 (até três ocorrências por tipo), '
        'mais 3 por fluxo inseguro (até cinco), limitado a 100. **Não é uma métrica oficial nem avalia risco real.**', '',
        '## Achados nos logs (valores mascarados)',
        '| Linha | Tipo | Risco | Evidência protegida |',
        '|---:|---|---|---|',
    ]
    linhas.extend(f'| {x["linha"]} | {x["tipo"]} | {x["nivel"]} | `{x["evidencia"]}` |'
                  for x in relatorio['ocorrencias'])
    linhas += ['', '## Taint Analysis — caminho dos dados', '']
    for f in relatorio['fluxos']:
        linhas.append(f'- **{f["status"]} — {f["tipo"]}** (`{f["funcao"]}`, L{f["linha"]}): ' +
                      ' → '.join(f['rastro']))
    b = relatorio['bloqueio']
    linhas += ['', '## Demonstração de bloqueio preventivo',
              f'- Mensagens de teste: **{b["tentativas"]}**.',
              f'- Mensagens bloqueadas pelo filtro: **{b["bloqueados"]}**.',
              f'- Mensagens permitidas: **{b["permitidos"]}**.',
              '- O filtro evita a escrita no **handler demonstrativo**. Não remove conteúdo de arquivos antigos, '
              'não cobre todos os formatos e não substitui controles aplicados aos demais destinos de log.', '',
              '## Tradução para o cidadão — texto com apoio de IA', relatorio['explicacao_simples'], '',
              '## Remediações por vulnerabilidade', '']
    for item in relatorio['remediacoes']:
        linhas += [f'### {item["tipo"]} — {item["titulo"]}',
                  f'- **Para o cidadão:** {item["linguagem_cidadao"]}',
                  f'- **Correção recomendada:** {item["acao_tecnica"]}', '']
    linhas += [
        '## Evidências para o vídeo e a entrega',
        '- `evidencias/01_dashboard_v2.png`: dashboard com índice Risco Cidadão.',
        '- `evidencias/02_taint_v2.png`: rastros seguros e inseguros no HTML.',
        '- `evidencias/03_execucao.txt`: saída real do analisador no terminal.',
        '- `evidencias/04_testes.txt`: saída real dos testes automatizados.',
        '- `evidencias/05_bloqueio.txt`: saída do filtro preventivo.',
        '- `evidencias/06_remediacao_v2.png`: painel com remediações assistidas por IA.',
        '- `evidencias/07_bloqueio_v2.png`: painel com a demonstração de bloqueio.',
        '- Para o vídeo, gravar o projeto **rodando no VS Code e no navegador**.', '',
        '## IA na elaboração (sem envio de PII)',
        'Os textos de impacto e remediação foram elaborados com auxílio do ChatGPT usando somente '
        'nomes de categorias e cenários **fictícios**, sem upload de logs reais. Ver `documentacao/uso_ia.md`.', '',
        '## Limitações e segurança',
        '- A análise AST não avalia fluxos entre funções, condicionais complexas, aliases nem a implementação real de todos os sanitizadores.',
        '- O motor regex pode produzir falsos positivos e falsos negativos; somente certos formatos e chaves são reconhecidos.',
        '- A análise não elimina vazamentos já existentes e a demonstração não equivale a proteção integral de produção.',
        '- Não armazenar nem submeter dados pessoais reais neste exercício.',
        '- O índice do dashboard é apenas didático. O projeto não certifica aderência à LGPD.', '',
    ]
    return '\n'.join(linhas)


def executar(log: Path, codigo: Path, pasta_saida: Path) -> dict:
    # Importação local mantém o motor de parsing reutilizável no bloqueador.
    from bloqueador import demonstrar_bloqueio
    linhas, ocorrencias = analisar_log(log)
    fluxos = analisar_codigo(codigo)
    bloqueio = demonstrar_bloqueio()
    contagens = Counter(x['tipo'] for x in ocorrencias)
    risco = calcular_risco(ocorrencias, fluxos)
    relatorio = {
        'projeto': 'Refresca SP — Auditoria de Cybersecurity',
        'versao': '2.0',
        'gerado_em_utc': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M'),
        'linhas_analisadas': linhas, 'ocorrencias': ocorrencias,
        'fluxos': fluxos, 'risco_geral': risco,
        'indice_cidadao': calcular_indice_cidadao(ocorrencias, fluxos),
        'bloqueio': bloqueio,
        'explicacao_simples': explicar_risco(risco, contagens),
        'remediacoes': remediacoes_por_tipo(ocorrencias, fluxos),
    }
    pasta_saida.mkdir(parents=True, exist_ok=True)
    (pasta_saida / 'auditoria.json').write_text(json.dumps(relatorio, ensure_ascii=False, indent=2), encoding='utf-8')
    (pasta_saida / 'dashboard.html').write_text(criar_dashboard(relatorio), encoding='utf-8')
    (pasta_saida / 'relatorio_auditoria.md').write_text(criar_relatorio_md(relatorio), encoding='utf-8')
    (pasta_saida / 'prova_bloqueio.txt').write_text(
        f"DEMONSTRAÇÃO DE FILTRO PREVENTIVO | REFRESCA SP\n"
        f"Tentativas: {bloqueio['tentativas']}\n"
        f"Bloqueadas: {bloqueio['bloqueados']}\n"
        f"Permitidas: {bloqueio['permitidos']}\n"
        f"Tipos bloqueados: {', '.join(f'{tipo}={qt}' for tipo, qt in bloqueio['tipos_bloqueados'].items())}\n"
        'Nenhuma mensagem recusada foi gravada no handler demonstrativo.\n', encoding='utf-8')
    return relatorio


def main() -> None:
    parser = argparse.ArgumentParser(description='Refresca SP | Auditoria isolada de dados sensíveis')
    parser.add_argument('--log', type=Path, default=BASE / 'dados' / 'log_simulado.txt')
    parser.add_argument('--codigo', type=Path, default=BASE / 'dados' / 'exemplo_fluxo.py')
    parser.add_argument('--saida', type=Path, default=BASE / 'saida')
    args = parser.parse_args()
    try:
        rel = executar(args.log, args.codigo, args.saida)
    except (FileNotFoundError, SyntaxError, UnicodeError, ValueError) as erro:
        parser.error(f'Falha na auditoria: {erro}')
    print('=' * 60)
    print('REFRESCA SP | AUDITORIA DE CYBERSECURITY — V2')
    print('=' * 60)
    print(f"Linhas de log .............. {rel['linhas_analisadas']}")
    print(f"Exposições detectadas ...... {len(rel['ocorrencias'])}")
    contagens = Counter(x['tipo'] for x in rel['ocorrencias'])
    for tipo in ('CPF', 'Telefone', 'Saúde', 'Senha'):
        print(f'{tipo:<25} {contagens[tipo]}')
    print(f"Fluxos vulneráveis ......... {sum(f['status'] == 'VULNERÁVEL' for f in rel['fluxos'])}")
    print(f"Fluxos protegidos .......... {sum(f['status'] == 'PROTEGIDO' for f in rel['fluxos'])}")
    print(f"Filtro: bloqueados ......... {rel['bloqueio']['bloqueados']}/{rel['bloqueio']['tentativas']}")
    print(f"Risco Cidadão .............. {rel['indice_cidadao']}/100 (didático)")
    print(f"Classificação geral ........ {rel['risco_geral']}")
    print('-' * 60)
    for x in rel['ocorrencias']:
        print(f"L{x['linha']:02} | {x['tipo']:<8} | {x['evidencia']}")
    print('-' * 60)
    print(f"Dashboard: {(args.saida / 'dashboard.html').resolve()}")
    print(f"Relatório: {(args.saida / 'relatorio_auditoria.md').resolve()}")
    print('Todos os dados de entrada da demonstração são fictícios.')


if __name__ == '__main__':
    main()
