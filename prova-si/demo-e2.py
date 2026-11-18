"""Demonstração da Entrega 2 com login real (E2E).

Diferença em relação ao demo.py:
- O demo.py usa um banco temporário e uma senha fictícia fixa, apenas para
  exibir mensagens possíveis de aceite/rejeição.
- Este script valida as credenciais DIGITADAS contra o banco real do app.py
  (usuarios.db). Se o login for correto, executa a demonstração de aceitação;
  caso contrário, exibe apenas mensagens de rejeição.

Uso: py demo-e2.py
     (cadastre antes o usuário via: py app.py -> opção 1)
"""

import copy
import json
import os
import sys
from getpass import getpass
from pathlib import Path


import auth
import cripto as c
import database
def ler_senha(rotulo: str) -> str:
    """Lê a senha de forma oculta no terminal; em pipes/automação lê em claro.

    Em uso interativo (terminal real), usa getpass para não ecoar a senha.
    Quando stdin vem de um pipe/arquivo (ex.: evidências automatizadas),
    getpass travaria, então lemos a linha normalmente.
    """
    if sys.stdin.isatty():
        return getpass(rotulo)
    print(rotulo, end="", flush=True)
    return input()

BANCO = Path(__file__).parent / "usuarios.db"
PASTA_CHAVES = Path(__file__).parent / "chaves_demo"
MENSAGEM = "Transferir R$ 100,00 para a conta 1234-5 (dados fictícios de teste)".encode("utf-8")


def titulo(texto: str) -> None:
    print(f"\n{'=' * 70}\n{texto}\n{'=' * 70}")


def tentar(descricao: str, funcao) -> None:
    try:
        resultado = funcao()
        print(f"[ACEITO]    {descricao}\n            -> {resultado.decode('utf-8', 'replace')}")
    except c.ErroVerificacao as erro:
        print(f"[REJEITADO] {descricao}\n            -> {erro}")


def adulterar_byte(b64_texto: str) -> str:
    """Inverte um bit do conteúdo Base64 para simular adulteração."""
    dados = bytearray(c._unb64(b64_texto))
    dados[0] ^= 0x01
    return c._b64(bytes(dados))


def demonstrar_rejeicao(motivo: str) -> None:
    titulo("DEMONSTRAÇÃO — LOGIN REJEITADO")
    print("[REJEITADO] Usuário ou senha inválidos.")
    print("            Acesso negado à demonstração.")
    if motivo:
        print(f"            ({motivo})")
    print("\nDica: cadastre um usuário primeiro com 'py app.py' (opção 1).")


def demonstrar_aceitacao(usuario: str) -> None:
    titulo(f"DEMONSTRAÇÃO — LOGIN ACEITO ({usuario})")
    print(f"[ACEITO] Autenticação bem-sucedida para {usuario!r}.")
    print("         Acesso concedido aos recursos do sistema.\n")
    demonstrar_autenticacao_real(usuario)
    demonstrar_criptografia()


def demonstrar_autenticacao_real(usuario: str) -> None:
    """Mostra o registro protegido do usuário autenticado no banco real."""
    titulo("ENTREGA 2 — REGISTRO PROTEGIDO NO BANCO REAL")
    hash_armazenado = database.obter_hash_senha(BANCO, usuario)
    print(f"Hash armazenado: {hash_armazenado}")
    print(f"Formato Argon2id: {str(hash_armazenado).startswith('$argon2id$')}")
    print("A senha original não é recuperável nem está gravada em texto puro.")


def demonstrar_criptografia() -> None:
    senha = os.environ.get("ENTREGA1_SENHA") or ler_senha(
        "Senha para proteger as chaves privadas da demonstração: "
    )
    senha_b = senha.encode("utf-8")

    titulo("ENTREGA 1 — 1. GERAÇÃO DE CHAVES")
    rsa_destino = c.gerar_chave_rsa()
    ed_remetente = c.gerar_chave_ed25519()
    c.salvar_chave_privada(rsa_destino, PASTA_CHAVES / "destino_rsa_privada.pem", senha_b)
    c.salvar_chave_publica(rsa_destino, PASTA_CHAVES / "destino_rsa_publica.pem")
    c.salvar_chave_privada(ed_remetente, PASTA_CHAVES / "remetente_ed25519_privada.pem", senha_b)
    c.salvar_chave_publica(ed_remetente, PASTA_CHAVES / "remetente_ed25519_publica.pem")
    print(f"Chaves salvas em: {PASTA_CHAVES} (privadas protegidas por senha, PKCS#8)")

    priv_rsa = c.carregar_chave_privada(PASTA_CHAVES / "destino_rsa_privada.pem", senha_b)
    pub_rsa = c.carregar_chave_publica(PASTA_CHAVES / "destino_rsa_publica.pem")
    priv_ed = c.carregar_chave_privada(PASTA_CHAVES / "remetente_ed25519_privada.pem", senha_b)
    pub_ed = c.carregar_chave_publica(PASTA_CHAVES / "remetente_ed25519_publica.pem")

    titulo("ENTREGA 1 — 2. FLUXO NORMAL: CIFRAR + ASSINAR / VERIFICAR + DECIFRAR")
    pacote = c.proteger(MENSAGEM, pub_rsa, priv_ed)
    dados = json.loads(pacote)
    print("Pacote transmitido (trecho):")
    print(f"  chave_cifrada : {dados['envelope']['chave_cifrada'][:48]}...")
    print(f"  texto_cifrado : {dados['envelope']['texto_cifrado'][:48]}...")
    print(f"  assinatura    : {dados['assinatura'][:48]}...")
    tentar("Pacote íntegro", lambda: c.abrir(pacote, priv_rsa, pub_ed))

    titulo("ENTREGA 1 — 3. FALHAS APÓS ADULTERAÇÃO")
    alterado = copy.deepcopy(dados)
    alterado["envelope"]["texto_cifrado"] = adulterar_byte(alterado["envelope"]["texto_cifrado"])
    tentar("3a. Texto cifrado alterado", lambda: c.abrir(json.dumps(alterado).encode(), priv_rsa, pub_ed))

    alterado = copy.deepcopy(dados)
    alterado["envelope"]["chave_cifrada"] = adulterar_byte(alterado["envelope"]["chave_cifrada"])
    tentar("3b. Chave AES encapsulada alterada", lambda: c.abrir(json.dumps(alterado).encode(), priv_rsa, pub_ed))

    alterado = copy.deepcopy(dados)
    alterado["envelope"]["alg"]["conteudo"] = "AES-128-GCM"
    tentar("3c. Cabeçalho/algoritmo alterado", lambda: c.abrir(json.dumps(alterado).encode(), priv_rsa, pub_ed))

    atacante_ed = c.gerar_chave_ed25519()
    alterado = copy.deepcopy(dados)
    alterado["envelope"]["texto_cifrado"] = adulterar_byte(alterado["envelope"]["texto_cifrado"])
    alterado["assinatura"] = c.assinar(alterado["envelope"], atacante_ed)
    tentar("3d. Atacante assina com sua própria chave Ed25519", lambda: c.abrir(json.dumps(alterado).encode(), priv_rsa, pub_ed))

    outra_rsa = c.gerar_chave_rsa()
    tentar("3e. Pacote aberto com chave RSA de outro destinatário", lambda: c.abrir(pacote, outra_rsa, pub_ed))

    envelope = copy.deepcopy(dados["envelope"])
    envelope["texto_cifrado"] = adulterar_byte(envelope["texto_cifrado"])
    tentar("3f. Tag GCM detecta adulteração mesmo sem assinatura", lambda: c.decifrar(envelope, priv_rsa))

    titulo("ENTREGA 1 — 4. SIGILO X AUTENTICIDADE")
    assinatura_aberta = c.assinar({"mensagem": MENSAGEM.decode("utf-8")}, priv_ed)
    print("(a) Apenas assinada: a mensagem está em claro, mas a origem pode ser verificada.")
    print(f"    Assinatura: {assinatura_aberta[:32]}...")
    forjada = c.cifrar("Pedido fictício forjado".encode("utf-8"), pub_rsa)
    print("(b) Apenas cifrada: qualquer pessoa com a chave pública pode criar uma cifra.")
    print(f"    Conteúdo recuperado: {c.decifrar(forjada, priv_rsa).decode('utf-8')}")
    tentar(
        "(c) A mesma forja é rejeitada no fluxo completo",
        lambda: c.abrir(
            json.dumps({"envelope": forjada, "assinatura": c.assinar(forjada, atacante_ed)}).encode(),
            priv_rsa,
            pub_ed,
        ),
    )


def main() -> None:
    database.inicializar_banco(BANCO)
    try:
        usuario = input("Usuário: ")
        senha = ler_senha("Senha: ")
    except EOFError:
        print("\nEntrada de dados interrompida.")
        return

    if auth.autenticar_usuario(BANCO, usuario, senha):
        demonstrar_aceitacao(usuario)
        titulo("DEMONSTRAÇÃO INTEGRADA CONCLUÍDA")
    else:
        demonstrar_rejeicao("usuário inexistente ou senha incorreta")


if __name__ == "__main__":
    main()
