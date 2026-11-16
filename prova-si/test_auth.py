"""Testes de cadastro e autenticação com Argon2id."""

import sqlite3

import pytest

import auth
import database


@pytest.fixture
def banco(tmp_path):
    caminho = tmp_path / "teste_usuarios.db"
    database.inicializar_banco(caminho)
    return caminho


def test_cadastro_gera_hash_argon2id(banco):
    auth.cadastrar_usuario(banco, "aluno", "senha-teste-123")
    senha_hash = database.obter_hash_senha(banco, "aluno")
    assert senha_hash is not None
    assert senha_hash.startswith("$argon2id$")


def test_banco_nao_armazena_senha_em_texto_puro(banco):
    senha = "senha-secreta-123"
    auth.cadastrar_usuario(banco, "aluno", senha)
    conteudo_banco = banco.read_bytes()
    assert senha.encode("utf-8") not in conteudo_banco
    assert senha not in database.obter_hash_senha(banco, "aluno")


def test_login_com_senha_correta(banco):
    auth.cadastrar_usuario(banco, "aluno", "senha-correta-123")
    assert auth.autenticar_usuario(banco, "aluno", "senha-correta-123") is True


def test_login_com_senha_incorreta(banco):
    auth.cadastrar_usuario(banco, "aluno", "senha-correta-123")
    assert auth.autenticar_usuario(banco, "aluno", "senha-errada-123") is False


def test_login_com_usuario_inexistente(banco):
    assert auth.autenticar_usuario(banco, "nao-existe", "senha-qualquer") is False


def test_usuario_duplicado_e_rejeitado(banco):
    auth.cadastrar_usuario(banco, "aluno", "senha-correta-123")
    with pytest.raises(database.UsuarioJaExisteError):
        auth.cadastrar_usuario(banco, "aluno", "outra-senha-123")


def test_usuario_duplicado_ignora_diferenca_de_maiusculas(banco):
    auth.cadastrar_usuario(banco, "Aluno", "senha-correta-123")
    with pytest.raises(database.UsuarioJaExisteError):
        auth.cadastrar_usuario(banco, "aluno", "outra-senha-123")


def test_mesma_senha_gera_hashes_diferentes_por_causa_do_salt(banco):
    auth.cadastrar_usuario(banco, "aluno1", "mesma-senha-123")
    auth.cadastrar_usuario(banco, "aluno2", "mesma-senha-123")
    hash1 = database.obter_hash_senha(banco, "aluno1")
    hash2 = database.obter_hash_senha(banco, "aluno2")
    assert hash1 != hash2


def test_senha_com_menos_de_oito_caracteres_e_rejeitada(banco):
    with pytest.raises(auth.DadosCadastroInvalidos):
        auth.cadastrar_usuario(banco, "aluno", "curta")


def test_usuario_curto_e_rejeitado(banco):
    with pytest.raises(auth.DadosCadastroInvalidos):
        auth.cadastrar_usuario(banco, "ab", "senha-correta-123")


def test_usuario_com_espacos_e_rejeitado(banco):
    with pytest.raises(auth.DadosCadastroInvalidos):
        auth.cadastrar_usuario(banco, "aluno teste", "senha-correta-123")


def test_hash_adulterado_e_rejeitado(banco):
    auth.cadastrar_usuario(banco, "aluno", "senha-correta-123")
    hash_original = database.obter_hash_senha(banco, "aluno")
    hash_adulterado = hash_original[:-1] + ("A" if hash_original[-1] != "A" else "B")
    with sqlite3.connect(banco) as conexao:
        conexao.execute(
            "UPDATE usuarios SET senha_hash = ? WHERE usuario = ?",
            (hash_adulterado, "aluno"),
        )
    assert auth.autenticar_usuario(banco, "aluno", "senha-correta-123") is False
