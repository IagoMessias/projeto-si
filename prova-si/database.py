"""Persistência SQLite para os usuários do projeto."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class UsuarioJaExisteError(Exception):
    """Indica que já existe uma conta com o nome informado."""


@contextmanager
def _conexao(caminho_db: str | Path) -> Iterator[sqlite3.Connection]:
    caminho = Path(caminho_db)
    caminho.parent.mkdir(parents=True, exist_ok=True)
    conexao = sqlite3.connect(caminho)
    try:
        yield conexao
        conexao.commit()
    except Exception:
        conexao.rollback()
        raise
    finally:
        conexao.close()


def inicializar_banco(caminho_db: str | Path) -> None:
    """Cria a tabela de usuários, caso ainda não exista."""
    with _conexao(caminho_db) as conexao:
        conexao.execute(
            """
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario TEXT NOT NULL UNIQUE COLLATE NOCASE,
                senha_hash TEXT NOT NULL,
                criado_em TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def inserir_usuario(caminho_db: str | Path, usuario: str, senha_hash: str) -> None:
    """Armazena o nome e o hash codificado; nunca recebe a senha original."""
    try:
        with _conexao(caminho_db) as conexao:
            conexao.execute(
                "INSERT INTO usuarios (usuario, senha_hash) VALUES (?, ?)",
                (usuario, senha_hash),
            )
    except sqlite3.IntegrityError as erro:
        raise UsuarioJaExisteError("Já existe uma conta com esse usuário.") from erro


def obter_hash_senha(caminho_db: str | Path, usuario: str) -> str | None:
    """Retorna o hash armazenado, ou None quando o usuário não existe."""
    with _conexao(caminho_db) as conexao:
        linha = conexao.execute(
            "SELECT senha_hash FROM usuarios WHERE usuario = ?",
            (usuario,),
        ).fetchone()
    return linha[0] if linha else None


def contar_usuarios(caminho_db: str | Path) -> int:
    """Retorna a quantidade de contas cadastradas (útil para testes)."""
    with _conexao(caminho_db) as conexao:
        linha = conexao.execute("SELECT COUNT(*) FROM usuarios").fetchone()
    return int(linha[0])
