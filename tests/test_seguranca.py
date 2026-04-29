import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from key_manager import gerar_par_de_chaves
from crypto_manager import cifrar_mensagem, decifrar_mensagem, salvar_pacote, deletar_pacote
from sign_manager import gerar_assinatura, verificar_assinatura
from main import nome_valido, mensagem_valida, LIMITE_MENSAGEM

class TestSegurancaPGP(unittest.TestCase):
    def setUp(self):
        self.alice_priv, self.alice_pub = gerar_par_de_chaves()
        self.bob_priv, self.bob_pub = gerar_par_de_chaves()
        self.trudy_priv, self.trudy_pub = gerar_par_de_chaves()
        self.mensagem = "Mensagem secreta de seguranca da informacao"

    def test_01_fluxo_sucesso(self):
        assinatura = gerar_assinatura(self.mensagem, self.alice_priv)
        pacote = cifrar_mensagem(self.mensagem, self.bob_pub, assinatura)
        msg_recebida, ass_recebida = decifrar_mensagem(pacote, self.bob_priv)
        valido = verificar_assinatura(msg_recebida, ass_recebida, self.alice_pub)

        self.assertTrue(valido)
        self.assertEqual(self.mensagem, msg_recebida)

    def test_02_falha_integridade(self):
        assinatura = gerar_assinatura(self.mensagem, self.alice_priv)
        pacote = cifrar_mensagem(self.mensagem, self.bob_pub, assinatura)
        msg_recebida, ass_recebida = decifrar_mensagem(pacote, self.bob_priv)

        msg_adulterada = "Mensagem capturada e alterada"
        valido = verificar_assinatura(msg_adulterada, ass_recebida, self.alice_pub)

        self.assertFalse(valido)

    def test_03_falha_confidencialidade(self):
        assinatura = gerar_assinatura(self.mensagem, self.alice_priv)
        pacote = cifrar_mensagem(self.mensagem, self.bob_pub, assinatura)

        with self.assertRaises(ValueError):
            decifrar_mensagem(pacote, self.trudy_priv)

    def test_04_assinatura_de_outro_remetente(self):
        assinatura = gerar_assinatura(self.mensagem, self.trudy_priv)
        pacote = cifrar_mensagem(self.mensagem, self.bob_pub, assinatura)
        msg_recebida, ass_recebida = decifrar_mensagem(pacote, self.bob_priv)
        valido = verificar_assinatura(msg_recebida, ass_recebida, self.alice_pub)

        self.assertFalse(valido)

    def test_05_nome_vazio(self):
        self.assertFalse(nome_valido(""))

    def test_06_nome_com_espaco(self):
        self.assertFalse(nome_valido("nome invalido"))

    def test_07_nome_com_acento(self):
        self.assertFalse(nome_valido("joão"))

    def test_08_nome_com_emoji(self):
        self.assertFalse(nome_valido("user😀"))

    def test_09_nome_valido(self):
        self.assertTrue(nome_valido("alice123"))

    def test_10_mensagem_vazia(self):
        self.assertFalse(mensagem_valida(""))

    def test_11_mensagem_com_acento(self):
        self.assertFalse(mensagem_valida("mensagem com acentuação"))

    def test_12_mensagem_com_emoji(self):
        self.assertFalse(mensagem_valida("ola mundo 😀"))

    def test_13_mensagem_valida(self):
        self.assertTrue(mensagem_valida("mensagem simples"))

    def test_14_mensagem_muito_longa(self):
        mensagem_longa = "a" * (LIMITE_MENSAGEM + 1)
        self.assertGreater(len(mensagem_longa), LIMITE_MENSAGEM)

    def test_15_mensagem_no_limite(self):
        mensagem_limite = "a" * LIMITE_MENSAGEM
        self.assertTrue(mensagem_valida(mensagem_limite))
        self.assertEqual(len(mensagem_limite), LIMITE_MENSAGEM)

    def test_16_deletar_mensagem(self):
        assinatura = gerar_assinatura(self.mensagem, self.alice_priv)
        pacote = cifrar_mensagem(self.mensagem, self.bob_pub, assinatura)
        salvar_pacote(pacote)
        resultado = deletar_pacote()
        self.assertTrue(resultado)

    def test_17_deletar_mensagem_inexistente(self):
        deletar_pacote()
        resultado = deletar_pacote()
        self.assertFalse(resultado)

if __name__ == '__main__':
    unittest.main()