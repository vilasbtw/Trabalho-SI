import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

KEYS_DIR = os.path.join("data", "keys")

def gerar_par_de_chaves():
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    chave_publica = chave_privada.public_key()
    return chave_privada, chave_publica

def salvar_chaves(nome_usuario, chave_privada, chave_publica):
    os.makedirs(KEYS_DIR, exist_ok=True)

    caminho_privada = os.path.join(KEYS_DIR, f"{nome_usuario}_priv.pem")
    with open(caminho_privada, "wb") as f:
        f.write(chave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    caminho_publica = os.path.join(KEYS_DIR, f"{nome_usuario}_pub.pem")
    with open(caminho_publica, "wb") as f:
        f.write(chave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

def carregar_chave_privada(nome_usuario):
    caminho = os.path.join(KEYS_DIR, f"{nome_usuario}_priv.pem")
    with open(caminho, "rb") as f:
        chave_privada = serialization.load_pem_private_key(f.read(), password=None)
    return chave_privada

def carregar_chave_publica(nome_usuario):
    caminho = os.path.join(KEYS_DIR, f"{nome_usuario}_pub.pem")
    with open(caminho, "rb") as f:
        chave_publica = serialization.load_pem_public_key(f.read())
    return chave_publica