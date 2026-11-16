"""
Uso:  python demo.py
Para repetir sem digitar a senha:  (PowerShell)  $env:ENTREGA1_SENHA="[Senha]"
"""

import copy
import json
import os
from getpass import getpass
from pathlib import Path

import cripto as c

PASTA_CHAVES = Path(__file__).parent / "chaves"  
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
    """Inverte um bit do conteúdo decodificado (simula adulteração em trânsito)."""
    dados = bytearray(c._unb64(b64_texto))
    dados[0] ^= 0x01
    return c._b64(bytes(dados))


def main() -> None:
    senha = os.environ.get("ENTREGA1_SENHA") or getpass("Senha para proteger as chaves privadas: ")
    senha_b = senha.encode("utf-8")

    titulo("1. GERAÇÃO DE CHAVES")
    rsa_destino = c.gerar_chave_rsa()        # par do serviço que RECEBE (sigilo)
    ed_remetente = c.gerar_chave_ed25519()   # par do serviço que ENVIA (autenticidade)
    c.salvar_chave_privada(rsa_destino, PASTA_CHAVES / "destino_rsa_privada.pem", senha_b)
    c.salvar_chave_publica(rsa_destino, PASTA_CHAVES / "destino_rsa_publica.pem")
    c.salvar_chave_privada(ed_remetente, PASTA_CHAVES / "remetente_ed25519_privada.pem", senha_b)
    c.salvar_chave_publica(ed_remetente, PASTA_CHAVES / "remetente_ed25519_publica.pem")
    print(f"Chaves salvas em: {PASTA_CHAVES}  (privadas protegidas por senha, PKCS#8)")

    # Recarrega do disco para provar que o fluxo funciona com os arquivos
    priv_rsa = c.carregar_chave_privada(PASTA_CHAVES / "destino_rsa_privada.pem", senha_b)
    pub_rsa = c.carregar_chave_publica(PASTA_CHAVES / "destino_rsa_publica.pem")
    priv_ed = c.carregar_chave_privada(PASTA_CHAVES / "remetente_ed25519_privada.pem", senha_b)
    pub_ed = c.carregar_chave_publica(PASTA_CHAVES / "remetente_ed25519_publica.pem")

    titulo("2. Fluxo Normal: cifrar + assinar -> verificar + decifrar")
    pacote = c.proteger(MENSAGEM, pub_rsa, priv_ed)
    dados = json.loads(pacote)
    print("Pacote transmitido (trecho):")
    print(f"  chave_cifrada : {dados['envelope']['chave_cifrada'][:48]}...")
    print(f"  texto_cifrado : {dados['envelope']['texto_cifrado'][:48]}...")
    print(f"  assinatura    : {dados['assinatura'][:48]}...")
    tentar("Pacote íntegro", lambda: c.abrir(pacote, priv_rsa, pub_ed))

    titulo("3. FALHAS APÓS ADULTERAÇÃO")

    # 3a. Adultera o texto cifrado, mantém a assinatura antiga
    d = copy.deepcopy(dados)
    d["envelope"]["texto_cifrado"] = adulterar_byte(d["envelope"]["texto_cifrado"])
    tentar("3a. Texto cifrado alterado (assinatura original mantida)",
           lambda: c.abrir(json.dumps(d).encode(), priv_rsa, pub_ed))

    # 3b. Adultera a chave encapsulada
    d = copy.deepcopy(dados)
    d["envelope"]["chave_cifrada"] = adulterar_byte(d["envelope"]["chave_cifrada"])
    tentar("3b. Chave encapsulada alterada",
           lambda: c.abrir(json.dumps(d).encode(), priv_rsa, pub_ed))

    # 3c. Adultera o cabeçalho (algoritmos declarados)
    d = copy.deepcopy(dados)
    d["envelope"]["alg"]["conteudo"] = "AES-128-GCM"
    tentar("3c. Cabeçalho/algoritmo alterado",
           lambda: c.abrir(json.dumps(d).encode(), priv_rsa, pub_ed))

    # 3d. Atacante adultera e RE-ASSINA com a própria chave
    atacante_ed = c.gerar_chave_ed25519()
    d = copy.deepcopy(dados)
    d["envelope"]["texto_cifrado"] = adulterar_byte(d["envelope"]["texto_cifrado"])
    d["assinatura"] = c.assinar(d["envelope"], atacante_ed)
    tentar("3d. Atacante adultera e assina com a PRÓPRIA chave Ed25519",
           lambda: c.abrir(json.dumps(d).encode(), priv_rsa, pub_ed))

    # 3e. Destinatário errado (chave RSA de outro serviço)
    outra_rsa = c.gerar_chave_rsa()
    tentar("3e. Pacote aberto com chave privada RSA de outro destinatário",
           lambda: c.abrir(pacote, outra_rsa, pub_ed))

    # 3f. Sem a camada de assinatura, o GCM ainda detecta adulteração
    env = copy.deepcopy(dados["envelope"])
    env["texto_cifrado"] = adulterar_byte(env["texto_cifrado"])
    tentar("3f. Decifrar direto (sem verificar assinatura): a tag GCM detecta a alteração",
           lambda: c.decifrar(env, priv_rsa))

    titulo("4. SIGILO x AUTENTICIDADE")
    # Só assinatura: autêntico, mas qualquer um lê.
    texto_claro = MENSAGEM
    assinatura_aberta = c.assinar({"mensagem": texto_claro.decode("utf-8")}, priv_ed)
    print("(a) Apenas ASSINADA: o conteúdo viaja em claro (sem sigilo),")
    print(f"    mas a origem é verificável. Assinatura: {assinatura_aberta[:32]}...")

    # Só cifragem: confidencial, mas qualquer um com a chave pública forja mensagens.
    forjada = c.cifrar("Transferir R$ 9.999,00 para o atacante".encode("utf-8"), pub_rsa)
    print("(b) Apenas CIFRADA: a chave pública é pública, então um atacante cria uma")
    print("    mensagem sigilosa válida. O destino a decifra sem saber quem a enviou:")
    print(f"    -> {c.decifrar(forjada, priv_rsa).decode('utf-8')}")
    tentar("(c) Mesma forja no fluxo completo (exige assinatura do remetente legítimo)",
           lambda: c.abrir(
               json.dumps({"envelope": forjada, "assinatura": c.assinar(forjada, atacante_ed)}).encode(),
               priv_rsa, pub_ed))


if __name__ == "__main__":
    main()
