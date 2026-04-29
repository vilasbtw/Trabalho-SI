import os
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes

MENSAGENS_DIR = os.path.join("data", "mensagens")

def cifrar_mensagem(mensagem, chave_publica_destinatario, assinatura):
    payload = mensagem.encode("utf-8")
    chave_sessao = os.urandom(32)
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    payload_com_padding = padder.update(payload) + padder.finalize()

    cipher = Cipher(algorithms.AES(chave_sessao), modes.CBC(iv))
    encryptor = cipher.encryptor()
    payload_cifrado = encryptor.update(payload_com_padding) + encryptor.finalize()

    chave_sessao_cifrada = chave_publica_destinatario.encrypt(
        chave_sessao,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    pacote = {
        "payload_cifrado": base64.b64encode(payload_cifrado).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "chave_sessao_cifrada": base64.b64encode(chave_sessao_cifrada).decode("utf-8"),
        "assinatura": base64.b64encode(assinatura).decode("utf-8"),
    }
    return pacote

def salvar_pacote(pacote, nome_arquivo="mensagem_cifrada.json"):
    os.makedirs(MENSAGENS_DIR, exist_ok=True)
    caminho = os.path.join(MENSAGENS_DIR, nome_arquivo)
    with open(caminho, "w") as f:
        json.dump(pacote, f, indent=4)

def carregar_pacote(nome_arquivo="mensagem_cifrada.json"):
    caminho = os.path.join(MENSAGENS_DIR, nome_arquivo)
    with open(caminho, "r") as f:
        pacote = json.load(f)
    return pacote

def deletar_pacote(nome_arquivo="mensagem_cifrada.json"):
    caminho = os.path.join(MENSAGENS_DIR, nome_arquivo)
    if os.path.exists(caminho):
        os.remove(caminho)
        return True
    return False

def decifrar_mensagem(pacote, chave_privada_destinatario):
    payload_cifrado = base64.b64decode(pacote["payload_cifrado"])
    iv = base64.b64decode(pacote["iv"])
    chave_sessao_cifrada = base64.b64decode(pacote["chave_sessao_cifrada"])
    assinatura = base64.b64decode(pacote["assinatura"])

    chave_sessao = chave_privada_destinatario.decrypt(
        chave_sessao_cifrada,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    cipher = Cipher(algorithms.AES(chave_sessao), modes.CBC(iv))
    decryptor = cipher.decryptor()
    payload_com_padding = decryptor.update(payload_cifrado) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    payload = unpadder.update(payload_com_padding) + unpadder.finalize()

    mensagem = payload.decode("utf-8")
    return mensagem, assinatura
