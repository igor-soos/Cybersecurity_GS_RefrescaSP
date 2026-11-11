"""Testes locais (sem pytest, sem internet) para parsing, AST, bloqueio e saída."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from analisador import (
    analisar_linha, analisar_log, analisar_codigo, cpf_valido, mascara,
    calcular_risco, calcular_indice_cidadao, executar, criar_dashboard,
)
from bloqueador import FiltroPII, demonstrar_bloqueio
import logging
from io import StringIO


class TesteRegex(unittest.TestCase):
    def test_cpf_formatado_e_valido(self):
        self.assertTrue(cpf_valido('111.444.777-35'))
        self.assertEqual([x['tipo'] for x in analisar_linha('cpf=111.444.777-35', 1)], ['CPF'])

    def test_cpf_sem_pontuacao(self):
        self.assertEqual([x['tipo'] for x in analisar_linha('cpf=12345678909', 1)], ['CPF'])

    def test_cpf_invalido_sem_contexto(self):
        self.assertEqual(analisar_linha('ID: 11111111111', 1), [])

    def test_telefone_ddd(self):
        self.assertEqual([x['tipo'] for x in analisar_linha('telefone=(11) 98888-7777', 1)], ['Telefone'])

    def test_telefone_sem_mascara(self):
        self.assertEqual([x['tipo'] for x in analisar_linha('celular=11987654321', 1)], ['Telefone'])

    def test_telefone_com_55(self):
        self.assertEqual([x['tipo'] for x in analisar_linha('telefone=+55 11 97777-6666', 1)], ['Telefone'])

    def test_nao_confunde_cep_temperatura_e_id(self):
        self.assertEqual(analisar_linha('cep=01310-100 temperature=36.5 distance=200m id=REF-105', 1), [])

    def test_nao_sinaliza_campos_mascarados(self):
        self.assertEqual(analisar_linha('cpf=***.***.***-35 telefone=(**) *****-7777 saude=[OCULTO] senha=[OCULTO]', 1), [])

    def test_detecta_diagnostico_com_aspas(self):
        self.assertEqual([x['tipo'] for x in analisar_linha('diagnostico="hipertensao"', 1)], ['Saúde'])

    def test_detecta_condicao_saude_sem_aspas(self):
        self.assertEqual([x['tipo'] for x in analisar_linha('condicao_saude=diabetes', 1)], ['Saúde'])

    def test_detecta_saude_com_formato_json(self):
        self.assertEqual([x['tipo'] for x in analisar_linha('{"saude":"dado simulado"}', 1)], ['Saúde'])

    def test_detecta_senha_e_password(self):
        self.assertEqual([x['tipo'] for x in analisar_linha('senha=segredo_falso password=teste123', 1)], ['Senha', 'Senha'])

    def test_cpf_dentro_de_senha_nao_cria_duplicata(self):
        achados = analisar_linha('senha=111.444.777-35', 1)
        self.assertEqual([x['tipo'] for x in achados], ['Senha'])

    def test_nao_detecta_palavras_soltas(self):
        self.assertEqual(analisar_linha('Ajuda para a saude e troca de senha disponivel', 1), [])

    def test_nao_reexpor_textos_privados(self):
        entrada = 'cpf=111.444.777-35 telefone=11987654321 diagnostico="hipertensao" senha="segredo_fake"'
        texto = json.dumps(analisar_linha(entrada, 1), ensure_ascii=False)
        for valor in ('111.444.777-35', '11987654321', 'hipertensao', 'segredo_fake'):
            self.assertNotIn(valor, texto)
        self.assertIn('[SEGREDO OCULTO]', texto)

    def test_valores_mascarados(self):
        self.assertEqual(mascara('Senha', 'meusegredo'), '[SEGREDO OCULTO]')
        self.assertEqual(mascara('Saúde', 'hipertensao'), '[DADO DE SAÚDE OCULTO]')

    def test_contagem_arquivo_de_exemplo(self):
        linhas, achados = analisar_log(BASE / 'dados' / 'log_simulado.txt')
        self.assertEqual(linhas, 14)
        self.assertEqual(len(achados), 11)


class TesteTaint(unittest.TestCase):
    def test_identifica_quatro_inseguros_quatro_protegidos(self):
        fluxos = analisar_codigo(BASE / 'dados' / 'exemplo_fluxo.py')
        self.assertEqual(sum(f['status'] == 'VULNERÁVEL' for f in fluxos), 4)
        self.assertEqual(sum(f['status'] == 'PROTEGIDO' for f in fluxos), 4)
        self.assertEqual(set(f['tipo'] for f in fluxos), {'CPF', 'Telefone', 'Senha', 'Saúde'})

    def test_rastros_fonte_destino(self):
        fluxos = analisar_codigo(BASE / 'dados' / 'exemplo_fluxo.py')
        for fluxo in fluxos:
            self.assertIn('Entrada:', fluxo['rastro'][0])
            self.assertIn('Destino:', fluxo['rastro'][-1])

    def test_sanitizador_de_cpf_nao_protege_senha(self):
        codigo = "def f(payload):\n    senha = payload['senha']\n    logger.info(mascarar_cpf(senha))\n"
        with tempfile.TemporaryDirectory() as temp:
            caminho = Path(temp) / 'ex.py'
            caminho.write_text(codigo, encoding='utf-8')
            fluxo = analisar_codigo(caminho)
        self.assertEqual(fluxo[0]['status'], 'VULNERÁVEL')

    def test_logger_com_argumentos_de_formatacao(self):
        codigo = "def f(payload):\n    doc = payload['cpf']\n    logger.info('cpf=%s', doc)\n"
        with tempfile.TemporaryDirectory() as temp:
            caminho = Path(temp) / 'ex.py'
            caminho.write_text(codigo, encoding='utf-8')
            fluxo = analisar_codigo(caminho)
        self.assertEqual(fluxo[0]['tipo'], 'CPF')
        self.assertEqual(fluxo[0]['status'], 'VULNERÁVEL')

    def test_risco_critico_e_indice(self):
        _, achados = analisar_log(BASE / 'dados' / 'log_simulado.txt')
        fluxos = analisar_codigo(BASE / 'dados' / 'exemplo_fluxo.py')
        self.assertEqual(calcular_risco(achados, fluxos), 'CRÍTICO')
        self.assertEqual(calcular_indice_cidadao(achados, fluxos), 91)

    def test_sem_risco(self):
        self.assertEqual(calcular_risco([], []), 'BAIXO')
        self.assertEqual(calcular_indice_cidadao([], []), 0)


class TesteBloqueio(unittest.TestCase):
    def test_demonstra_quatro_bloqueios(self):
        resultado = demonstrar_bloqueio()
        self.assertEqual((resultado['tentativas'], resultado['bloqueados'], resultado['permitidos']), (6, 4, 2))
        self.assertTrue(resultado['nenhuma_exposicao_no_handler'])

    def test_filtro_nao_escreve_senha(self):
        memoria = StringIO()
        logger = logging.Logger('teste_local_refresca', level=logging.INFO)
        logger.propagate = False
        handler = logging.StreamHandler(memoria)
        filtro = FiltroPII()
        handler.addFilter(filtro)
        logger.addHandler(handler)
        logger.info('senha=%s', 'senha_ficticia_supersecreta')
        logger.info('status=OK cadastro_id=CAD-999')
        handler.flush()
        texto = memoria.getvalue()
        self.assertNotIn('senha_ficticia_supersecreta', texto)
        self.assertIn('status=OK', texto)
        self.assertEqual(len(filtro.bloqueios), 1)
        logger.removeHandler(handler)
        handler.close()

    def test_bloqueia_saude(self):
        filtro = FiltroPII()
        record = logging.LogRecord('test', logging.INFO, __file__, 1, 'diagnostico="hipertensao"', (), None)
        self.assertFalse(filtro.filter(record))
        self.assertEqual(filtro.bloqueios[0], ['Saúde'])


class TesteArtefatos(unittest.TestCase):
    def test_relatorio_dashboard_json_sem_dados_em_claro(self):
        with tempfile.TemporaryDirectory() as temp:
            destino = Path(temp)
            saida = executar(BASE / 'dados' / 'log_simulado.txt',
                             BASE / 'dados' / 'exemplo_fluxo.py', destino)
            self.assertEqual(saida['indice_cidadao'], 91)
            for nome in ('auditoria.json', 'dashboard.html', 'relatorio_auditoria.md', 'prova_bloqueio.txt'):
                conteudo = (destino / nome).read_text(encoding='utf-8')
                for segredo in ('111.444.777-35', '11987654321', 'hipertensao', 'diabetes',
                                'senha_ficticia_123', 'ChaveTesteABC'):
                    self.assertNotIn(segredo, conteudo, f'Falha em {nome}')

    def test_dashboard_inclui_secao_remediacao_e_bloqueio(self):
        with tempfile.TemporaryDirectory() as temp:
            result = executar(BASE / 'dados' / 'log_simulado.txt',
                              BASE / 'dados' / 'exemplo_fluxo.py', Path(temp))
            html = criar_dashboard(result)
        for titulo in ('Indicador Risco Cidadão', 'Bloqueio preventivo', 'Remediação traduzida',
                       'Taint Analysis', '91', 'CRÍTICO'):
            self.assertIn(titulo, html)


if __name__ == '__main__':
    unittest.main()
