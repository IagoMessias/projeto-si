"""
Gera um pacote protegido em arquivo para você ALTERAR À MÃO e ver o sistema reagir.

Uso:
  py teste_manual.py gerar                   cria chaves_teste/ e chaves_teste/pacote.json
  py teste_manual.py abrir                   verifica e abre o pacote
  py teste_manual.py abrir --outro-destino   tenta abrir com a chave RSA de outro destinatário

Senha das chaves de teste: variável TESTE_SENHA (padrão: senha-de-teste-manual).
"""

import os
import sys
from pathlib import Path

import cripto as c

PASTA = Path(__file__).parent / "chaves_teste"
PACOTE = PASTA / "pacote.json"
MENSAGEM = "Mensagem de teste manual (dados fictícios)".encode("utf-8")


def senha() -> bytes:
    return os.environ.get("TESTE_SENHA", "senha-de-teste-manual").encode("utf-8")


def gerar() -> None:
    rsa_destino = c.gerar_chave_rsa()
    ed_remetente = c.gerar_chave_ed25519()
    c.salvar_chave_privada(rsa_destino, PASTA / "destino_rsa_privada.pem", senha())
    c.salvar_chave_publica(rsa_destino, PASTA / "destino_rsa_publica.pem")
    c.salvar_chave_privada(ed_remetente, PASTA / "remetente_ed_privada.pem", senha())
    c.salvar_chave_publica(ed_remetente, PASTA / "remetente_ed_publica.pem")
    PACOTE.write_bytes(c.proteger(MENSAGEM, rsa_destino.public_key(), ed_remetente))
    print(f"Pacote gerado: {PACOTE}")
    print("Agora edite o arquivo à mão (Bloco de Notas), salve e rode: py teste_manual.py abrir")


def abrir(outro_destino: bool) -> None:
    try:
        pacote = PACOTE.read_bytes()
        pub_ed = c.carregar_chave_publica(PASTA / "remetente_ed_publica.pem")
        if outro_destino:
            priv_rsa = c.gerar_chave_rsa()  # chave de um destinatário diferente
            print("(usando uma chave RSA de OUTRO destinatário)")
        else:
            priv_rsa = c.carregar_chave_privada(PASTA / "destino_rsa_privada.pem", senha())
    except FileNotFoundError as erro:
        print(f"[ERRO] Arquivo não encontrado: {erro.filename}. Rode primeiro: py teste_manual.py gerar")
        return
    except ValueError:
        print("[ERRO] Não foi possível carregar a chave privada: senha incorreta ou arquivo corrompido.")
        return

    try:
        texto = c.abrir(pacote, priv_rsa, pub_ed)
        print(f"[ACEITO]    {texto.decode('utf-8')}")
    except c.ErroVerificacao as erro:
        print(f"[REJEITADO] {erro}")


def main() -> None:
    args = sys.argv[1:]
    if args == ["gerar"]:
        gerar()
    elif args and args[0] == "abrir":
        abrir("--outro-destino" in args)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
