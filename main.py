import re
from key_manager import gerar_par_de_chaves, salvar_chaves, carregar_chave_privada, carregar_chave_publica
from crypto_manager import cifrar_mensagem, salvar_pacote, carregar_pacote, decifrar_mensagem, deletar_pacote
from sign_manager import gerar_assinatura, verificar_assinatura

LIMITE_MENSAGEM = 100

def nome_valido(nome):
    return bool(re.fullmatch(r'[a-zA-Z0-9]+', nome))

def mensagem_valida(mensagem):
    return bool(re.fullmatch(r'[a-zA-Z0-9 ]+', mensagem))

def setup_usuario():
    print("\n--- CADASTRO DE USUÁRIO ---")
    nome = input("Digite o nome de usuário: ").strip().lower()
    if not nome:
        print("[ERRO] Nome inválido.")
        return
    if not nome_valido(nome):
        print("[ERRO] Nome de usuário deve conter apenas letras e números, sem espaços ou caracteres especiais.")
        return
    chave_privada, chave_publica = gerar_par_de_chaves()
    salvar_chaves(nome, chave_privada, chave_publica)
    print(f"[OK] Usuário '{nome}' configurado.")

def enviar_mensagem():
    print("\n--- ENVIAR MENSAGEM ---")
    remetente = input("Seu usuário: ").strip().lower()
    destinatario = input("Destinatário: ").strip().lower()
    mensagem = input("Mensagem: ").strip()

    if not all([remetente, destinatario, mensagem]):
        print("[ERRO] Preencha todos os campos.")
        return

    if not nome_valido(remetente) or not nome_valido(destinatario):
        print("[ERRO] Nomes de usuário devem conter apenas letras e números.")
        return

    if remetente == destinatario:
        print("[ERRO] Você não pode enviar uma mensagem para si mesmo.")
        return

    if not mensagem_valida(mensagem):
        print("[ERRO] A mensagem deve conter apenas letras, números e espaços.")
        return

    if len(mensagem) > LIMITE_MENSAGEM:
        print(f"[ERRO] A mensagem não pode ter mais de {LIMITE_MENSAGEM} caracteres.")
        return

    try:
        chave_privada_remetente = carregar_chave_privada(remetente)
        chave_publica_destinatario = carregar_chave_publica(destinatario)
    except FileNotFoundError:
        print("[ERRO] Usuário não encontrado.")
        return

    assinatura = gerar_assinatura(mensagem, chave_privada_remetente)
    pacote = cifrar_mensagem(mensagem, chave_publica_destinatario, assinatura)
    salvar_pacote(pacote)
    print("\n[OK] Mensagem enviada com sucesso.")

def receber_mensagem():
    print("\n--- LER MENSAGEM ---")
    destinatario = input("Seu usuário: ").strip().lower()
    remetente = input("Remetente: ").strip().lower()

    try:
        chave_privada_destinatario = carregar_chave_privada(destinatario)
        chave_publica_remetente = carregar_chave_publica(remetente)
    except FileNotFoundError:
        print("[ERRO] Usuário não encontrado.")
        return

    try:
        pacote = carregar_pacote()
    except FileNotFoundError:
        print("[ERRO] Nenhuma mensagem encontrada.")
        return

    try:
        mensagem, assinatura = decifrar_mensagem(pacote, chave_privada_destinatario)
    except ValueError:
        print("\n[ALERTA] Falha na decifragem! Você não tem permissão para ler esta mensagem ou ela foi corrompida.")
        return

    assinatura_valida = verificar_assinatura(mensagem, assinatura, chave_publica_remetente)

    if not assinatura_valida:
        print("\n[ALERTA] Assinatura inválida! O conteúdo pode ter sido alterado.")
        return

    print("\n--- CONTEÚDO SEGURO ---")
    print(f"De: {remetente}")
    print(f"Mensagem: {mensagem}")
    print("[OK] Autenticidade confirmada.")

def deletar_mensagem():
    print("\n--- DELETAR MENSAGEM ---")
    removido = deletar_pacote()
    if removido:
        print("[OK] Mensagem deletada com sucesso.")
    else:
        print("[ERRO] Nenhuma mensagem encontrada para deletar.")

def menu():
    while True:
        print("\n=== SISTEMA DE MENSAGENS PGP ===")
        print("1. Cadastrar Usuário")
        print("2. Enviar Mensagem")
        print("3. Receber Mensagem")
        print("4. Deletar Mensagem")
        print("0. Sair")

        opcao = input("Opção: ").strip()

        if opcao == "1":
            setup_usuario()
        elif opcao == "2":
            enviar_mensagem()
        elif opcao == "3":
            receber_mensagem()
        elif opcao == "4":
            deletar_mensagem()
        elif opcao == "0":
            break
        else:
            print("[ERRO] Opção inválida.")

if __name__ == "__main__":
    menu()
