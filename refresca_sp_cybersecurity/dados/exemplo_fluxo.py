"""Apenas para inspeção AST; NÃO importe a função insegura em aplicação real."""
import logging

logger = logging.getLogger('refresca_sp')


def mascarar_cpf(valor: str) -> str:
    nums = ''.join(c for c in valor if c.isdigit())
    return '***.***.***-' + nums[-2:]


def mascarar_telefone(valor: str) -> str:
    nums = ''.join(c for c in valor if c.isdigit())
    return '(**) *****-' + nums[-4:]


def ocultar_senha(_valor: str) -> str:
    return '[SEGREDO OCULTO]'


def ocultar_saude(_valor: str) -> str:
    return '[DADO DE SAÚDE OCULTO]'


def cadastrar_usuario_inseguro(payload: dict) -> None:
    cpf = payload['cpf']            # SOURCE: usuário
    telefone = payload['telefone']  # SOURCE: usuário
    senha = payload['senha']        # SOURCE: usuário
    saude = payload['saude']        # SOURCE: usuário
    mensagem = f'cpf={cpf}, telefone={telefone}, senha={senha}, saude={saude}'
    logger.info(mensagem)          # SINK: envia tudo sem proteção


def cadastrar_usuario_seguro(payload: dict) -> None:
    cpf = payload['cpf']
    telefone = payload['telefone']
    senha = payload['senha']
    saude = payload['saude']
    logger.info('Cadastro: cpf=%s tel=%s senha=%s saude=%s',
                mascarar_cpf(cpf), mascarar_telefone(telefone),
                ocultar_senha(senha), ocultar_saude(saude))
