"""Cadastro e autenticação usando Argon2id."""

from __future__ import annotations

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

import database

# OWASP ASVS 5.0.0: Argon2id com m >= 46 MiB, t = 1 e p = 1.
ARGON2_MEMORY_COST = 47_104  # KiB (46 MiB)
ARGON2_TIME_COST = 1
ARGON2_PARALLELISM = 1
ARGON2_SALT_LENGTH = 16
ARGON2_HASH_LENGTH = 32

TAMANHO_MINIMO_SENHA = 8
TAMANHO_MINIMO_USUARIO = 3
TAMANHO_MAXIMO_USUARIO = 32

_HASHER = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LENGTH,
    salt_len=ARGON2_SALT_LENGTH,
    type=Type.ID,
)


class DadosCadastroInvalidos(ValueError):
    """Dados de cadastro não atendem às validações da aplicação."""


def gerar_hash_senha(senha: str) -> str:
    """Gera um hash Argon2id com salt aleatório criado pela biblioteca."""
    if not isinstance(senha, str):
        raise TypeError("A senha deve ser texto.")
    if len(senha) < TAMANHO_MINIMO_SENHA:
        raise DadosCadastroInvalidos(
            f"A senha deve ter pelo menos {TAMANHO_MINIMO_SENHA} caracteres."
        )
    return _HASHER.hash(senha)


def verificar_senha(senha: str, senha_hash: str) -> bool:
    """Usa a comparação de verificação implementada pela biblioteca Argon2."""
    if not isinstance(senha, str) or not isinstance(senha_hash, str):
        return False
    try:
        return _HASHER.verify(senha_hash, senha)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def cadastrar_usuario(caminho_db: str, usuario: str, senha: str) -> None:
    """Valida, calcula o hash e grava a conta no SQLite."""
    if not isinstance(usuario, str):
        raise DadosCadastroInvalidos("O usuário deve ser texto.")
    usuario = usuario.strip()
    if not TAMANHO_MINIMO_USUARIO <= len(usuario) <= TAMANHO_MAXIMO_USUARIO:
        raise DadosCadastroInvalidos(
            f"O usuário deve ter entre {TAMANHO_MINIMO_USUARIO} e "
            f"{TAMANHO_MAXIMO_USUARIO} caracteres."
        )
    if any(caractere.isspace() for caractere in usuario):
        raise DadosCadastroInvalidos("O usuário não pode conter espaços.")

    senha_hash = gerar_hash_senha(senha)
    database.inicializar_banco(caminho_db)
    database.inserir_usuario(caminho_db, usuario, senha_hash)


def autenticar_usuario(caminho_db: str, usuario: str, senha: str) -> bool:
    """Retorna True apenas quando o usuário existe e a senha confere."""
    if not isinstance(usuario, str) or not isinstance(senha, str):
        return False
    usuario = usuario.strip()
    if not usuario or not senha:
        return False

    database.inicializar_banco(caminho_db)
    senha_hash = database.obter_hash_senha(caminho_db, usuario)
    if senha_hash is None:
        return False
    return verificar_senha(senha, senha_hash)
