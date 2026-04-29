import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from key_manager import gerar_par_de_chaves
from crypto_manager import cifrar_mensagem, decifrar_mensagem
from sign_manager import gerar_assinatura, verificar_assinatura

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

if __name__ == '__main__':
    unittest.main()