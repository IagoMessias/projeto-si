"""Demonstração da Entrega 3: varredura controlada de portas e serviços.

Mantém o LOGIN OBRIGATÓRIO do demo_e2.py. No modo sem --alvo usa arquivos
didáticos de amostra, sem executar Nmap. Com --alvo executa a varredura real.
"""
from __future__ import annotations

import argparse
from getpass import getpass
from pathlib import Path

import analise_portas as ap
import auditoria_ssh as ssh
import auth
import database
import varredura as vr

BANCO = Path(__file__).parent / "usuarios.db"
PASTA_EVIDENCIAS = Path(__file__).parent / "evidencias"
AMOSTRAS = Path(__file__).parent / "amostras"


def titulo(texto: str) -> None:
    print(f"\n{'=' * 70}\n{texto}\n{'=' * 70}")


def autenticar() -> bool:
    titulo("ENTREGA 3 — LOGIN OBRIGATÓRIO (MESMO BANCO DO APP)")
    database.inicializar_banco(BANCO)
    if database.contar_usuarios(BANCO) == 0:
        print("[ERRO] Nenhum usuário cadastrado neste banco.")
        print("       Cadastre um com: py app.py (opção 1) e rode o demo_e3 novamente.")
        return False
    usuario = input("Nome de usuário: ").strip()
    senha = getpass("Senha: ")
    if auth.autenticar_usuario(BANCO, usuario, senha):
        print(f"[ACEITO] Login de {usuario!r} realizado com sucesso.")
        return True
    print("[REJEITADO] Usuário ou senha inválidos. Demonstração não executada.")
    return False


def testar_alvo(escopo, alvo: str) -> bool:
    try:
        ip = vr.validar_alvo(alvo, escopo)
        print(f"[ACEITO]    Alvo {alvo!r} está no escopo -> {ip}")
        return True
    except vr.ErroEscopo as erro:
        print(f"[REJEITADO] Alvo {alvo!r}\n            -> {erro}")
        return False


def etapa_escopo(escopo, alvo: str | None) -> bool:
    titulo("1. ESCOPO E AUTORIZAÇÃO")
    print(f"Responsável       : {escopo.responsavel}")
    print(f"Finalidade        : {escopo.finalidade}")
    print(f"Autorizado por    : {escopo.autorizado_por}")
    print(f"Válida de/até     : {escopo.data_autorizacao} / {escopo.validade_ate}")
    print(f"Redes autorizadas : {', '.join(str(r) for r in escopo.redes)}")
    print(f"Portas no escopo  : {escopo.portas}")
    print("Serviços necessários:")
    for s in escopo.servicos_necessarios:
        print(f"  - {s['porta']}/{s['protocolo']}: {s['justificativa']}")
    print("\nTeste de bloqueio (o escopo impede alvos não autorizados):")
    testar_alvo(escopo, "8.8.8.8")
    testar_alvo(escopo, "scanme.nmap.org")
    testar_alvo(escopo, "192.168.56.1; dir")
    testar_alvo(escopo, "127.0.0.2")
    return testar_alvo(escopo, alvo) if alvo else True


def etapa_varredura(escopo, args):
    titulo("2. VARREDURA DE PORTAS E SERVIÇOS")
    if args.alvo:
        try:
            xml, comando = vr.executar_nmap(
                args.alvo, escopo, portas=args.portas, udp=args.udp, rotulo=args.rotulo
            )
        except (vr.ErroNmap, vr.ErroEscopo) as erro:
            print(f"[ERRO] {erro}")
            return None, None
        print(f"Comando executado:\n  {comando}")
        print(f"Saída XML salva em: {xml}")
        ip_normalizado = vr.validar_alvo(args.alvo, escopo)
        modo = f"{args.rotulo}_{str(ip_normalizado).replace('.', '-')}"
    else:
        xml = AMOSTRAS / "nmap_lab_exemplo.xml"
        print("[AMOSTRA] Dados de exemplo (offline). NÃO são evidência da varredura real.")
        modo = "amostra"
    resultado = vr.ler_xml(xml)
    print(
        f"Hosts ativos: {resultado.hosts_ativos} | "
        f"portas abertas confirmadas: {len(resultado.portas)} | "
        f"estados indeterminados: {len(resultado.indeterminadas)}"
    )
    if resultado.indeterminadas:
        print("[INFO] open|filtered não é confirmação de porta aberta; pode estar filtrada.")
    return resultado, modo


def etapa_tabela(escopo, resultado, modo: str):
    titulo("3. TABELA PORTA / PROTOCOLO / SERVIÇO / RISCO / RECOMENDAÇÃO")
    achados = ap.classificar(resultado.portas, escopo)
    print(ap.tabela_texto(achados))
    faltando = ap.ausentes(resultado.portas, escopo)
    for s in faltando:
        print(f"[ATENÇÃO] Serviço necessário não encontrado aberto: {s['porta']}/{s['protocolo']} ({s['justificativa']})")
    pasta_saida = (AMOSTRAS / "saidas") if modo == "amostra" else PASTA_EVIDENCIAS
    csv_ = ap.salvar_csv(achados, pasta_saida / f"entrega3_tabela_{modo}.csv")
    md = ap.salvar_markdown(achados, pasta_saida / f"entrega3_tabela_{modo}.md")
    print(f"Tabelas salvas em:\n  {csv_}\n  {md}")
    for p in resultado.portas:
        if p.servico == "ssh" and p.scripts:
            print(f"\nInformações do SSH coletadas pelo Nmap na porta {p.porta}/{p.protocolo}:")
            for nome, saida in p.scripts.items():
                linhas = [l for l in saida.splitlines() if l.strip()][:8]
                print(f"  [{nome}]")
                for l in linhas:
                    print(f"  {l}")
    return achados


def etapa_ssh(sshd_config: str | None, rotulo: str) -> dict:
    titulo("4. AUDITORIA DO SSH (BOAS PRÁTICAS DE AUTENTICAÇÃO REMOTA)")
    if sshd_config:
        achados = ssh.auditar_windows_arquivo(sshd_config)
        print(f"Arquivo analisado: {sshd_config}\n")
        print(ssh.tabela_texto(achados))
        r = ssh.resumo(achados)
        resumo_texto = f"Resumo: {r['OK']} OK | {r['ATENÇÃO']} atenção | {r['FALHA']} falha(s)"
        print(f"\n{resumo_texto}")
        PASTA_EVIDENCIAS.mkdir(parents=True, exist_ok=True)
        arquivo_saida = PASTA_EVIDENCIAS / f"entrega3_ssh_{rotulo}.txt"
        arquivo_saida.write_text(
            f"ENTREGA 3 - AUDITORIA SSH ({rotulo.upper()})\n"
            f"Arquivo analisado: {sshd_config}\n\n"
            f"{ssh.tabela_texto(achados)}\n\n{resumo_texto}\n",
            encoding="utf-8",
        )
        print(f"Evidência SSH salva em: {arquivo_saida}")
        return {rotulo: r}
    print("[AMOSTRA] Comparação didática de configurações do OpenSSH para Windows.")
    resumos = {}
    for rotulo, nome in (("antes", "sshd_config_inseguro.conf"),
                         ("depois", "sshd_config_endurecido.conf")):
        achados = ssh.auditar_windows_arquivo(AMOSTRAS / nome)
        resumos[rotulo] = ssh.resumo(achados)
        print(f"\n--- {rotulo.upper()} ({nome}) ---")
        print(ssh.tabela_texto(achados))
        r = resumos[rotulo]
        print(f"Resumo: {r['OK']} OK | {r['ATENÇÃO']} atenção | {r['FALHA']} falha(s)")
    return resumos


def etapa_superficie(achados, resumos_ssh: dict) -> None:
    titulo("5. REDUÇÃO DA SUPERFÍCIE DE ATAQUE (PROPOSTA)")
    r = ap.resumo(achados)
    print(f"Portas abertas: {r['abertas']} (necessárias: {r['necessarias']}, desnecessárias: {r['desnecessarias']})")
    print(f"Risco: {r['alto']} alto | {r['medio']} médio | {r['baixo']} baixo")
    if r["a_fechar"]:
        print(f"Fechar: {', '.join(r['a_fechar'])}")
        print(f"Portas abertas depois da proposta: {r['necessarias']} (redução de {r['desnecessarias']})")
    else:
        print("Nenhuma porta desnecessária encontrada.")
    print("Demais medidas: manter o OpenSSH vinculado a 127.0.0.1, preferir chaves,")
    print("desativar autenticação por senha e encerrar o servidor HTTP extra (porta 8001).")
    if "antes" in resumos_ssh and "depois" in resumos_ssh:
        print(
            f"SSH (amostra): falhas {resumos_ssh['antes']['FALHA']} -> {resumos_ssh['depois']['FALHA']}, "
            f"atenções {resumos_ssh['antes']['ATENÇÃO']} -> {resumos_ssh['depois']['ATENÇÃO']}"
        )


def executar(args) -> None:
    try:
        escopo = vr.carregar_escopo()
    except vr.ErroEscopo as erro:
        print(f"[ERRO] Escopo inválido: {erro}")
        return
    if not etapa_escopo(escopo, args.alvo):
        titulo("DEMONSTRAÇÃO ENCERRADA: ALVO FORA DO ESCOPO")
        return
    resultado, modo = etapa_varredura(escopo, args)
    if resultado is None:
        return
    achados = etapa_tabela(escopo, resultado, modo)
    resumos = etapa_ssh(args.sshd_config, args.rotulo)
    etapa_superficie(achados, resumos)
    titulo("DEMONSTRAÇÃO DA ENTREGA 3 CONCLUÍDA (LOGIN ACEITO)")


def ler_argumentos(argv=None):
    parser = argparse.ArgumentParser(description="Demonstração da Entrega 3 (varredura controlada).")
    parser.add_argument("--alvo", help="use somente 127.0.0.1 (loopback do próprio Windows)")
    parser.add_argument(
        "--portas",
        help="portas TCP autorizadas no laboratório local, ex.: 22,8000-8001",
    )
    parser.add_argument(
        "--udp", action="store_true",
        help="varredura UDP das portas autorizadas selecionadas (exige administrador)",
    )
    parser.add_argument("--rotulo", default="antes", help="rótulo da evidência: antes ou depois (padrão: antes)")
    parser.add_argument("--sshd-config", dest="sshd_config", help="arquivo sshd_config ou saída de 'sshd -T'")
    return parser.parse_args(argv)


def main() -> None:
    args = ler_argumentos()
    if not autenticar():
        titulo("DEMONSTRAÇÃO ENCERRADA: LOGIN REJEITADO")
        return
    executar(args)


if __name__ == "__main__":
    main()
