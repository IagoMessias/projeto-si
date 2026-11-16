"""Interface simples de terminal para cadastro e login."""

from getpass import getpass
from pathlib import Path

import auth
import database

BANCO = Path(__file__).parent / "usuarios.db"


def main() -> None:
    database.inicializar_banco(BANCO)
    while True:
        print("\n=== SISTEMA DE CADASTRO E LOGIN ===")
        print("1 - Cadastrar usuário")
        print("2 - Fazer login")
        print("3 - Sair")
        opcao = input("Escolha uma opção: ").strip()

        if opcao == "1":
            usuario = input("Nome de usuário: ")
            senha = getpass("Senha (mínimo de 8 caracteres): ")
            try:
                auth.cadastrar_usuario(BANCO, usuario, senha)
                print("[OK] Cadastro realizado com sucesso.")
            except auth.DadosCadastroInvalidos as erro:
                print(f"[ERRO] {erro}")
            except database.UsuarioJaExisteError:
                print("[ERRO] Já existe uma conta com esse usuário.")

        elif opcao == "2":
            usuario = input("Nome de usuário: ")
            senha = getpass("Senha: ")
            if auth.autenticar_usuario(BANCO, usuario, senha):
                print("[OK] Login realizado com sucesso.")
            else:
                # Mensagem genérica para não informar se o usuário existe.
                print("[REJEITADO] Usuário ou senha inválidos.")

        elif opcao == "3":
            print("Encerrando o programa.")
            break
        else:
            print("Opção inválida. Escolha 1, 2 ou 3.")


if __name__ == "__main__":
    main()
