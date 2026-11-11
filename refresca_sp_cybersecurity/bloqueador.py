"""Demonstração isolada de bloqueio de logs sensíveis com logging.Filter.

Filtros de log só protegem os handlers onde forem instalados. Este código
não intercepta stdout, arquivos antigos, terceiros ou outras aplicações.
"""
from __future__ import annotations

from collections import Counter
from io import StringIO
import logging

from analisador import analisar_linha


class FiltroPII(logging.Filter):
    """Descarta mensagens cujo texto formatado contenha PII reconhecida."""

    def __init__(self) -> None:
        super().__init__()
        self.bloqueios: list[list[str]] = []

    def filter(self, record: logging.LogRecord) -> bool:
        achados = analisar_linha(record.getMessage(), 1)
        if achados:
            # Somente tipos são mantidos; nem o record nem a mensagem original.
            self.bloqueios.append(sorted(set(a['tipo'] for a in achados)))
            return False
        return True


def demonstrar_bloqueio() -> dict:
    destino = StringIO()
    logger = logging.Logger('refresca_sp_demo_bloqueio', level=logging.INFO)
    logger.propagate = False
    handler = logging.StreamHandler(destino)
    handler.setFormatter(logging.Formatter('%(levelname)s | %(message)s'))
    filtro = FiltroPII()
    handler.addFilter(filtro)
    logger.addHandler(handler)

    # Exemplos inventados apenas para teste acadêmico, sem dados de cidadãos.
    mensagens = [
        'cadastro_id=CAD-201 cpf=111.444.777-35 status=RECEBIDO',
        'cadastro_id=CAD-202 telefone=(11) 98888-7777 status=RECEBIDO',
        'cadastro_id=CAD-203 senha=senha_ficticia_123 status=RECEBIDO',
        'cadastro_id=CAD-204 diagnostico="hipertensao" status=RECEBIDO',
        'cadastro_id=CAD-205 status=RECEBIDO',
        'cadastro_id=CAD-206 cpf=***.***.***-35 status=RECEBIDO',
    ]
    for mensagem in mensagens:
        logger.info('%s', mensagem)
    handler.flush()
    saida = destino.getvalue()
    handler.close()
    logger.removeHandler(handler)
    # Evita reexpor mensagens completas; somente resumo numérico.
    classes = Counter(t for itens in filtro.bloqueios for t in itens)
    return {
        'tentativas': len(mensagens),
        'bloqueados': len(filtro.bloqueios),
        'permitidos': len(mensagens) - len(filtro.bloqueios),
        'tipos_bloqueados': dict(classes),
        'linhas_escritas_no_handler': len(saida.splitlines()),
        'nenhuma_exposicao_no_handler': all(not analisar_linha(s, 1) for s in saida.splitlines()),
    }


if __name__ == '__main__':
    resultado = demonstrar_bloqueio()
    print('REFRESCA SP | DEMONSTRAÇÃO DE BLOQUEIO')
    print(f"Tentativas: {resultado['tentativas']}")
    print(f"Bloqueadas: {resultado['bloqueados']}")
    print(f"Permitidas: {resultado['permitidos']}")
    print(f"Linhas realmente gravadas: {resultado['linhas_escritas_no_handler']}")
    print('Dados sensíveis gravados: NÃO' if resultado['nenhuma_exposicao_no_handler'] else 'ATENÇÃO: revisar filtro')
    print('Observação: proteção demonstrativa aplicada somente a um handler isolado.')
