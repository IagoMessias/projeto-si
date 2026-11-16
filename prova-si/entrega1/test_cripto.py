"""Testes positivos e negativos. Executar com:  pytest -v"""

import copy
import json

import pytest

import cripto as c

MSG = "mensagem de teste com acentuação: ção ✓".encode("utf-8")


@pytest.fixture(scope="module")
def chaves():
    return {
        "rsa": c.gerar_chave_rsa(),
        "rsa_outra": c.gerar_chave_rsa(),
        "ed": c.gerar_chave_ed25519(),
        "ed_atacante": c.gerar_chave_ed25519(),
    }


def _flip(b64_texto: str, posicao: int = 0) -> str:
    dados = bytearray(c._unb64(b64_texto))
    dados[posicao] ^= 0x01
    return c._b64(bytes(dados))


# --- Positivos -------------------------------------------------------------
def test_parametros_minimos():
    chave = c.gerar_chave_rsa()
    assert chave.key_size >= 3072


def test_ida_e_volta(chaves):
    pacote = c.proteger(MSG, chaves["rsa"].public_key(), chaves["ed"])
    assert c.abrir(pacote, chaves["rsa"], chaves["ed"].public_key()) == MSG


def test_mensagem_vazia_e_grande(chaves):
    for msg in (b"", b"A" * 1_000_000):  # 1 MB: a cifragem híbrida não tem o limite do RSA
        pacote = c.proteger(msg, chaves["rsa"].public_key(), chaves["ed"])
        assert c.abrir(pacote, chaves["rsa"], chaves["ed"].public_key()) == msg


def test_texto_cifrado_nao_contem_texto_claro(chaves):
    pacote = c.proteger(MSG, chaves["rsa"].public_key(), chaves["ed"])
    assert MSG not in pacote


def test_nonce_e_chave_diferentes_a_cada_envio(chaves):
    e1 = c.cifrar(MSG, chaves["rsa"].public_key())
    e2 = c.cifrar(MSG, chaves["rsa"].public_key())
    assert e1["nonce"] != e2["nonce"]
    assert e1["texto_cifrado"] != e2["texto_cifrado"]
    assert e1["chave_cifrada"] != e2["chave_cifrada"]


def test_persistencia_de_chaves_em_pem(chaves, tmp_path):
    senha = b"senha-de-teste"
    c.salvar_chave_privada(chaves["rsa"], tmp_path / "rsa.pem", senha)
    c.salvar_chave_publica(chaves["rsa"], tmp_path / "rsa_pub.pem")
    assert b"ENCRYPTED PRIVATE KEY" in (tmp_path / "rsa.pem").read_bytes()
    recarregada = c.carregar_chave_privada(tmp_path / "rsa.pem", senha)
    pub = c.carregar_chave_publica(tmp_path / "rsa_pub.pem")
    assert c.decifrar(c.cifrar(MSG, pub), recarregada) == MSG


# --- Negativos: adulteração -------------------------------------------------
@pytest.mark.parametrize("campo", ["texto_cifrado", "chave_cifrada", "nonce"])
def test_adulteracao_de_campo_e_rejeitada(chaves, campo):
    pacote = json.loads(c.proteger(MSG, chaves["rsa"].public_key(), chaves["ed"]))
    pacote["envelope"][campo] = _flip(pacote["envelope"][campo])
    with pytest.raises(c.ErroVerificacao):
        c.abrir(json.dumps(pacote).encode(), chaves["rsa"], chaves["ed"].public_key())


def test_adulteracao_do_cabecalho_e_rejeitada(chaves):
    pacote = json.loads(c.proteger(MSG, chaves["rsa"].public_key(), chaves["ed"]))
    pacote["envelope"]["alg"]["conteudo"] = "AES-128-GCM"
    with pytest.raises(c.ErroVerificacao):
        c.abrir(json.dumps(pacote).encode(), chaves["rsa"], chaves["ed"].public_key())


def test_gcm_detecta_adulteracao_mesmo_sem_assinatura(chaves):
    env = c.cifrar(MSG, chaves["rsa"].public_key())
    env["texto_cifrado"] = _flip(env["texto_cifrado"])
    with pytest.raises(c.ErroVerificacao):
        c.decifrar(env, chaves["rsa"])


def test_cabecalho_alterado_falha_no_gcm_por_causa_do_aad(chaves):
    env = c.cifrar(MSG, chaves["rsa"].public_key())
    env["alg"] = {**env["alg"], "conteudo": "outro"}
    with pytest.raises(c.ErroVerificacao):
        c.decifrar(env, chaves["rsa"])


# --- Negativos: autenticidade e destinatário --------------------------------
def test_assinatura_de_atacante_e_rejeitada(chaves):
    pacote = json.loads(c.proteger(MSG, chaves["rsa"].public_key(), chaves["ed"]))
    pacote["assinatura"] = c.assinar(pacote["envelope"], chaves["ed_atacante"])
    with pytest.raises(c.ErroVerificacao):
        c.abrir(json.dumps(pacote).encode(), chaves["rsa"], chaves["ed"].public_key())


def test_forja_so_com_chave_publica_nao_passa_no_fluxo_completo(chaves):
    """Quem só tem a chave pública do destino consegue cifrar, mas não assinar como o remetente."""
    forjada = c.cifrar(b"pedido forjado", chaves["rsa"].public_key())
    assert c.decifrar(forjada, chaves["rsa"]) == b"pedido forjado"  # sigilo sem autenticidade
    pacote = {"envelope": forjada, "assinatura": c.assinar(forjada, chaves["ed_atacante"])}
    with pytest.raises(c.ErroVerificacao):
        c.abrir(json.dumps(pacote).encode(), chaves["rsa"], chaves["ed"].public_key())


def test_destinatario_errado_nao_decifra(chaves):
    pacote = c.proteger(MSG, chaves["rsa"].public_key(), chaves["ed"])
    with pytest.raises(c.ErroVerificacao):
        c.abrir(pacote, chaves["rsa_outra"], chaves["ed"].public_key())


def test_assinatura_nao_vale_para_outro_envelope(chaves):
    """Replay de assinatura em outro conteúdo deve falhar."""
    p1 = json.loads(c.proteger(b"um", chaves["rsa"].public_key(), chaves["ed"]))
    p2 = json.loads(c.proteger(b"dois", chaves["rsa"].public_key(), chaves["ed"]))
    p2["assinatura"] = p1["assinatura"]
    with pytest.raises(c.ErroVerificacao):
        c.abrir(json.dumps(p2).encode(), chaves["rsa"], chaves["ed"].public_key())


@pytest.mark.parametrize("lixo", [b"", b"nao e json", b"{}", b'{"envelope": 1, "assinatura": 2}'])
def test_pacote_malformado(chaves, lixo):
    with pytest.raises(c.ErroVerificacao):
        c.abrir(lixo, chaves["rsa"], chaves["ed"].public_key())


def test_senha_errada_nao_carrega_chave_privada(chaves, tmp_path):
    c.salvar_chave_privada(chaves["ed"], tmp_path / "ed.pem", b"correta")
    with pytest.raises(ValueError):
        c.carregar_chave_privada(tmp_path / "ed.pem", b"errada")
