"""Demonstração da Entrega 2 protegida por login real.

Uso: py demo_e2.py

Diferente do demo.py (que apenas mostra mensagens possíveis usando um banco
temporário), este script exige usuário e senha cadastrados no mesmo banco do
app.py (usuarios.db). Somente com login correto as demonstrações de ACEITAÇÃO
são executadas; caso contrário, a tentativa é registrada como REJEIÇÃO e o
programa encerra sem rodar a demonstração.
"""

import copy
import json
import os
import tempfile
from getpass import getpass
from pathlib import Path

import auth
import cripto as c
import database

BANCO = Path(__file__).parent / "usuarios.db"
PASTA_CHAVES = Path(__file__).parent / "chaves_demo"
MENSAGEM = "Transferir R$ 100,00 para a conta 1234-5 (dados fictícios de teste)".encode("utf-8")


def titulo(texto: str) -> None:
    print(f"\n{'=' * 70}\n{texto}\n{'=' * 70}")


def tentar(descricao: str, funcao) -> None:
    try:
        resultado = funcao()
        if isinstance(resultado, (bytes, bytearray)):
            resultado = resultado.decode("utf-8", "replace")
        print(f"[ACEITO]    {descricao}\n            -> {resultado}")
    except c.ErroVerificacao as erro:
        print(f"[REJEITADO] {descricao}\n            -> {erro}")


def adulterar_byte(b64_texto: str) -> str:
    """Inverte um bit do conteúdo Base64 para simular adulteração."""
    dados = bytearray(c._unb64(b64_texto))
    dados[0] ^= 0x01
    return c._b64(bytes(dados))


def autenticar() -> bool:
    """Pede usuário e senha e valida contra o mesmo banco usado pelo app.py."""
    titulo("ENTREGA 2 — LOGIN OBRIGATÓRIO (MESMO BANCO DO APP)")
    database.inicializar_banco(BANCO)
    if database.contar_usuarios(BANCO) == 0:
        print("[ERRO] Nenhum usuário cadastrado neste banco.")
        print("       Cadastre um com: py app.py (opção 1) e rode o demo_e2 novamente.")
        return False

    usuario = input("Nome de usuário: ").strip()
    senha = getpass("Senha: ")
    if auth.autenticar_usuario(BANCO, usuario, senha):
        print(f"[ACEITO] Login de {usuario!r} realizado com sucesso.")
        return True
    # Mensagem genérica: não revela se o usuário existe (mesma política do app.py).
    print("[REJEITADO] Usuário ou senha inválidos. Demonstração não executada.")
    return False


def obter_senha_chaves(nova: bool) -> bytes:
    """Obtém a senha das chaves sem armazená-la no código."""
    senha_ambiente = os.environ.get("ENTREGA1_SENHA")
    if senha_ambiente is not None:
        if not senha_ambiente:
            raise RuntimeError("A variável ENTREGA1_SENHA está vazia.")
        return senha_ambiente.encode("utf-8")

    if not nova:
        senha = getpass("Senha das chaves privadas existentes: ")
        if not senha:
            raise RuntimeError("A senha das chaves não pode estar vazia.")
        return senha.encode("utf-8")

    while True:
        senha = getpass("Defina uma senha para proteger as novas chaves privadas: ")
        if not senha:
            print("A senha não pode estar vazia.")
            continue

        confirmacao = getpass("Confirme a senha: ")
        if senha != confirmacao:
            print("As senhas não coincidem. Tente novamente.")
            continue

        return senha.encode("utf-8")


def carregar_ou_gerar_chaves():
    """Reaproveita chaves existentes ou gera um novo par protegido por senha."""
    arquivos = {
        "priv_rsa": PASTA_CHAVES / "destino_rsa_privada.pem",
        "pub_rsa": PASTA_CHAVES / "destino_rsa_publica.pem",
        "priv_ed": PASTA_CHAVES / "remetente_ed25519_privada.pem",
        "pub_ed": PASTA_CHAVES / "remetente_ed25519_publica.pem",
    }
    existentes = [caminho.exists() for caminho in arquivos.values()]

    if all(existentes):
        senha_chaves = obter_senha_chaves(nova=False)
        try:
            return (
                c.carregar_chave_privada(arquivos["priv_rsa"], senha_chaves),
                c.carregar_chave_publica(arquivos["pub_rsa"]),
                c.carregar_chave_privada(arquivos["priv_ed"], senha_chaves),
                c.carregar_chave_publica(arquivos["pub_ed"]),
            )
        except Exception as erro:
            raise RuntimeError(
                "Não foi possível carregar as chaves existentes. "
                "Confira a senha e a integridade dos arquivos. "
                "As chaves não foram sobrescritas."
            ) from erro

    if any(existentes):
        raise RuntimeError(
            f"O conjunto de chaves em {PASTA_CHAVES} está incompleto. "
            "Faça uma cópia de segurança e confira os arquivos antes de gerar novas chaves. "
            "Os arquivos existentes não foram sobrescritos."
        )

    senha_chaves = obter_senha_chaves(nova=True)
    rsa_destino = c.gerar_chave_rsa()
    ed_remetente = c.gerar_chave_ed25519()
    c.salvar_chave_privada(rsa_destino, arquivos["priv_rsa"], senha_chaves)
    c.salvar_chave_publica(rsa_destino, arquivos["pub_rsa"])
    c.salvar_chave_privada(ed_remetente, arquivos["priv_ed"], senha_chaves)
    c.salvar_chave_publica(ed_remetente, arquivos["pub_ed"])
    print(f"Chaves novas salvas em: {PASTA_CHAVES} (privadas protegidas pela senha escolhida).")
    return (
        c.carregar_chave_privada(arquivos["priv_rsa"], senha_chaves),
        c.carregar_chave_publica(arquivos["pub_rsa"]),
        c.carregar_chave_privada(arquivos["priv_ed"], senha_chaves),
        c.carregar_chave_publica(arquivos["pub_ed"]),
    )


def demonstrar_criptografia() -> None:
    titulo("ENTREGA 1 — CHAVES E FLUXO CIFRAR + ASSINAR / VERIFICAR + DECIFRAR")
    PASTA_CHAVES.mkdir(parents=True, exist_ok=True)
    priv_rsa, pub_rsa, priv_ed, pub_ed = carregar_ou_gerar_chaves()

    pacote = c.proteger(MENSAGEM, pub_rsa, priv_ed)
    tentar("Pacote íntegro", lambda: c.abrir(pacote, priv_rsa, pub_ed))

    titulo("ENTREGA 1 — FALHAS APÓS ADULTERAÇÃO")
    dados = json.loads(pacote)
    alterado = copy.deepcopy(dados)
    alterado["envelope"]["texto_cifrado"] = adulterar_byte(alterado["envelope"]["texto_cifrado"])
    tentar("Texto cifrado alterado", lambda: c.abrir(json.dumps(alterado).encode(), priv_rsa, pub_ed))

    atacante_ed = c.gerar_chave_ed25519()
    outra_rsa = c.gerar_chave_rsa()
    tentar("Pacote aberto com chave RSA de outro destinatário", lambda: c.abrir(pacote, outra_rsa, pub_ed))
    forjada = c.cifrar("Pedido fictício forjado".encode("utf-8"), pub_rsa)
    tentar(
        "Forja assinada com chave Ed25519 do atacante",
        lambda: c.abrir(
            json.dumps({"envelope": forjada, "assinatura": c.assinar(forjada, atacante_ed)}).encode(),
            priv_rsa,
            pub_ed,
        ),
    )


def demonstrar_autenticacao() -> None:
    titulo("ENTREGA 2 — CADASTRO E AUTENTICAÇÃO COM ARGON2ID (BANCO TEMPORÁRIO)")
    with tempfile.TemporaryDirectory(prefix="demo_e2_") as pasta_temp:
        banco_temp = Path(pasta_temp) / "usuarios_demo.db"
        usuario = "aluno_demo"
        senha_ficticia = "Senha-Ficticia-123"

        auth.cadastrar_usuario(banco_temp, usuario, senha_ficticia)
        hash_armazenado = database.obter_hash_senha(banco_temp, usuario)
        print(f"[ACEITO] Cadastro de {usuario!r} realizado.")
        print(f"Hash armazenado: {hash_armazenado}")
        print(f"Formato Argon2id: {hash_armazenado.startswith('$argon2id$')}")

        login_correto = auth.autenticar_usuario(banco_temp, usuario, senha_ficticia)
        login_incorreto = auth.autenticar_usuario(banco_temp, usuario, "Senha-Errada-123")
        print(f"[{'ACEITO' if login_correto else 'REJEITADO'}] Login com senha correta.")
        print(f"[{'ACEITO' if login_incorreto else 'REJEITADO'}] Login com senha incorreta.")
    print("Banco temporário removido ao final da demonstração.")


def main() -> None:
    if not autenticar():
        titulo("DEMONSTRAÇÃO ENCERRADA: LOGIN REJEITADO")
        return
    try:
        demonstrar_criptografia()
    except RuntimeError as erro:
        print(f"[ERRO] {erro}")
        return
    demonstrar_autenticacao()
    titulo("DEMONSTRAÇÃO DA ENTREGA 2 CONCLUÍDA (LOGIN ACEITO)")


if __name__ == "__main__":
    main()
