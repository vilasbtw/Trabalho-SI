# Trabalho-SI - Sistema de Mensagens PGP

**Disciplina:** Segurança da Informação  
**Integrantes:** Kaique Vilas Boa · Evelyn Theodoro · Kauany das Graças

---

## Sobre o projeto

Este projeto implementa um sistema de troca de mensagens seguro via terminal, baseado nos princípios do PGP e no modelo de proteção fim a fim descrito por Kurose & Ross em *Computer Networks*. A arquitetura é híbrida: o corpo da mensagem é cifrado com AES-256-CBC usando uma chave de sessão única por envio, e essa chave é envelopada com RSA-2048 para o destinatário. Antes da cifragem, o remetente assina a mensagem com sua chave privada, garantindo autenticidade e integridade no recebimento.

---

## Funcionalidades

| Recurso | Descrição |
|---|---|
| **Cadastro de Usuário** | Gera e salva localmente um par de chaves RSA-2048 para o usuário |
| **Envio Seguro** | Assina a mensagem com RSA-PSS, cifra o conteúdo com AES-256-CBC e envelopa a chave de sessão com RSA-OAEP |
| **Recepção e Validação** | Decifra a chave de sessão com a chave privada, decifra a mensagem e verifica a assinatura digital do remetente |
| **Alerta de Segurança** | Rejeita a leitura e exibe alerta caso a assinatura seja inválida ou a mensagem tenha sido adulterada |
| **Deleção de Mensagem** | Remove o pacote cifrado do disco com segurança |
| **Validação de Entrada** | Bloqueia nomes e mensagens com caracteres especiais, acentos, emojis e entradas vazias |

---

## Como executar

### 1. Clonar o repositório

```bash
git clone https://github.com/vilasbtw/Trabalho-SI.git
cd Trabalho-SI
```

### 2. Instalar a dependência

```bash
pip install cryptography
```

### 3. Iniciar o sistema

```bash
python main.py
```

---

## Como usar

Após iniciar o sistema, o menu principal será exibido:

```
=== SISTEMA DE MENSAGENS PGP ===
1. Cadastrar Usuário
2. Enviar Mensagem
3. Receber Mensagem
4. Deletar Mensagem
0. Sair
```

### Fluxo completo recomendado

```
1 → Cadastrar usuário "alice"
1 → Cadastrar usuário "bob"
2 → Enviar mensagem (remetente: alice, destinatário: bob)
3 → Receber mensagem (seu usuário: bob, remetente: alice)
4 → Deletar mensagem
```

### Cadastrar Usuário
Escolha `1` e informe um nome de usuário contendo apenas letras e números, sem espaços ou caracteres especiais. O sistema gera e salva o par de chaves RSA na pasta `data/keys/`.

### Enviar Mensagem
Escolha `2`, informe seu usuário, o destinatário e a mensagem (limite de 100 caracteres, apenas letras, números e espaços). O sistema assina, cifra e exporta o pacote para `data/mensagens/mensagem_cifrada.json`.

### Receber Mensagem
Escolha `3`, informe seu usuário e o remetente esperado. O sistema decifra a mensagem e valida a assinatura. Se a assinatura for inválida ou a mensagem tiver sido adulterada, um alerta de segurança é exibido.

### Deletar Mensagem
Escolha `4` para remover o pacote cifrado do disco.

---

## Testes

O projeto conta com 17 testes unitários organizados em três categorias.

```bash
python -m unittest tests/test_seguranca.py -v
```

O resultado esperado é:

```
test_01_fluxo_sucesso ... ok
test_02_falha_integridade ... ok
...
test_17_deletar_mensagem_inexistente ... ok

Ran 17 tests in 3.4s
OK
```

Para rodar um teste específico:

```bash
python -m unittest tests.test_seguranca.TestSegurancaPGP.test_03_falha_confidencialidade -v
```
