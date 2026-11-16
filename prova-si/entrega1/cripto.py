from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Parâmetros 
RSA_BITS = 3072          
RSA_EXPOENTE = 65537
AES_BITS = 256
NONCE_BYTES = 12         
VERSAO = 1
ALGORITMOS = {
    "encapsulamento": "RSA-OAEP-SHA256",
    "conteudo": "AES-256-GCM",
    "assinatura": "Ed25519",
}

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


class ErroVerificacao(Exception):
    """Falha de autenticidade, integridade ou decifragem (mensagem genérica de propósito)."""


# Utilitários 
def _b64(dados: bytes) -> str:
    return base64.b64encode(dados).decode("ascii")


def _unb64(texto: str) -> bytes:
    if not isinstance(texto, str):
        raise ValueError("Campo base64 deve ser texto.")
    return base64.b64decode(texto.encode("ascii"), validate=True)


def _canonico(obj: dict) -> bytes:
    """Serialização determinística (necessária para assinar e para usar como AAD)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# Geração e armazenamento de chaves
def gerar_chave_rsa() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=RSA_EXPOENTE, key_size=RSA_BITS)


def gerar_chave_ed25519() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def salvar_chave_privada(chave, caminho: Path, senha: bytes) -> None:
    """Grava a chave privada em PEM (PKCS#8) protegida por senha."""
    pem = chave.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(senha),
    )
    caminho = Path(caminho)
    caminho.parent.mkdir(parents=True, exist_ok=True)
    caminho.write_bytes(pem)
    try:
        os.chmod(caminho, 0o600)  
    except OSError:
        pass


def salvar_chave_publica(chave, caminho: Path) -> None:
    pem = chave.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    caminho = Path(caminho)
    caminho.parent.mkdir(parents=True, exist_ok=True)
    caminho.write_bytes(pem)


def carregar_chave_privada(caminho: Path, senha: bytes):
    return serialization.load_pem_private_key(Path(caminho).read_bytes(), password=senha)


def carregar_chave_publica(caminho: Path):
    return serialization.load_pem_public_key(Path(caminho).read_bytes())


# Sigilo: cifragem híbrida 
def cifrar(mensagem: bytes, chave_publica_rsa) -> dict:
    """Cifra `mensagem` com AES-256-GCM e encapsula a chave AES com RSA-OAEP."""
    chave_aes = AESGCM.generate_key(bit_length=AES_BITS)
    nonce = os.urandom(NONCE_BYTES)
    cabecalho = {"v": VERSAO, "alg": ALGORITMOS}
    # O cabeçalho entra como AAD: se for alterado, a tag GCM deixa de validar.
    texto_cifrado = AESGCM(chave_aes).encrypt(nonce, mensagem, _canonico(cabecalho))
    chave_cifrada = chave_publica_rsa.encrypt(chave_aes, _OAEP)
    return {
        **cabecalho,
        "chave_cifrada": _b64(chave_cifrada),
        "nonce": _b64(nonce),
        "texto_cifrado": _b64(texto_cifrado),  
    }


def decifrar(envelope: dict, chave_privada_rsa) -> bytes:
    """Reverte `cifrar`. Lança ErroVerificacao se qualquer parte tiver sido alterada."""
    try:
        cabecalho = {"v": envelope["v"], "alg": envelope["alg"]}
        chave_aes = chave_privada_rsa.decrypt(_unb64(envelope["chave_cifrada"]), _OAEP)
        return AESGCM(chave_aes).decrypt(
            _unb64(envelope["nonce"]),
            _unb64(envelope["texto_cifrado"]),
            _canonico(cabecalho),
        )
    except (InvalidTag, ValueError, KeyError, TypeError):
        # Mensagem única: não revela se falhou o RSA ou o GCM (evita oráculos).
        raise ErroVerificacao("Falha ao decifrar: dados inválidos, alterados ou chave incorreta.")


# Autenticidade: assinatura digital 
def assinar(envelope: dict, chave_privada_ed) -> str:
    return _b64(chave_privada_ed.sign(_canonico(envelope)))


def verificar_assinatura(envelope: dict, assinatura_b64: str, chave_publica_ed) -> None:
    try:
        chave_publica_ed.verify(_unb64(assinatura_b64), _canonico(envelope))
    except (InvalidSignature, ValueError, TypeError):
        raise ErroVerificacao("Assinatura inválida: origem não confirmada ou mensagem alterada.")


# Fluxo completo 
def proteger(mensagem: bytes, pub_rsa_destino, priv_ed_remetente) -> bytes:
    """Remetente: cifra para o destino e assina o envelope (encrypt-then-sign)."""
    envelope = cifrar(mensagem, pub_rsa_destino)
    pacote = {"envelope": envelope, "assinatura": assinar(envelope, priv_ed_remetente)}
    return json.dumps(pacote, indent=2).encode("utf-8")


def abrir(pacote: bytes, priv_rsa_destino, pub_ed_remetente) -> bytes:
    """Destino: verifica a assinatura ANTES de decifrar; só então abre o conteúdo."""
    try:
        dados = json.loads(pacote.decode("utf-8"))
        envelope, assinatura = dados["envelope"], dados["assinatura"]
    except (ValueError, KeyError, TypeError):
        raise ErroVerificacao("Pacote malformado.")
    verificar_assinatura(envelope, assinatura, pub_ed_remetente)
    return decifrar(envelope, priv_rsa_destino)
