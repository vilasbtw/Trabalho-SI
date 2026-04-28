from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def gerar_assinatura(mensagem, chave_privada_remetente):
    payload = mensagem.encode("utf-8")
    
    assinatura = chave_privada_remetente.sign(
        payload,
        rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            salt_length=rsa_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return assinatura

def verificar_assinatura(mensagem, assinatura, chave_publica_remetente):
    payload = mensagem.encode("utf-8")
    
    try:
        chave_publica_remetente.verify(
            assinatura,
            payload,
            rsa_padding.PSS(
                mgf=rsa_padding.MGF1(hashes.SHA256()),
                salt_length=rsa_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False