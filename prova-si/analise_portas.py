"""Entrega 3 - Análise das portas encontradas: necessidade, risco e recomendação.

Compara o que está EXPOSTO (resultado do Nmap) com o que é NECESSÁRIO (escopo_lab.json).
Lembrete: porta aberta = ponto de acesso possível; serviço necessário não significa
configuração segura.
"""
from __future__ import annotations

import csv
import textwrap
from pathlib import Path

NIVEIS = ("Baixo", "Médio", "Alto")
CATALOGO = {
    (21, "tcp"): ("FTP", "Alto", "Autenticação e dados em texto claro; alvo comum de força bruta.",
                  "Substituir por SFTP (via SSH); se mantido, exigir TLS e restringir a origem."),
    (22, "tcp"): ("SSH", "Médio", "Acesso remoto; alvo de força bruta quando aceita senha.",
                  "Autenticação por chave, PasswordAuthentication no, PermitRootLogin no e serviço vinculado somente a 127.0.0.1."),
    (23, "tcp"): ("Telnet", "Alto", "Sessão remota sem criptografia: a senha trafega em texto claro.", "Substituir por SSH."),
    (25, "tcp"): ("SMTP", "Médio", "Pode permitir relay aberto e enumeração de usuários.", "Restringir origens, exigir TLS e autenticação."),
    (53, "tcp"): ("DNS", "Médio", "Pode ser usado em amplificação e vazamento de zonas.", "Desabilitar transferência de zona e consultas recursivas externas."),
    (53, "udp"): ("DNS", "Médio", "Pode ser usado em ataques de amplificação.", "Restringir consultas recursivas às redes internas."),
    (80, "tcp"): ("HTTP", "Médio", "Tráfego sem criptografia e superfície web ampla.", "Redirecionar para HTTPS, manter o servidor atualizado e ocultar a versão."),
    (110, "tcp"): ("POP3", "Alto", "Credenciais e e-mails em texto claro.", "Usar POP3S ou desativar."),
    (111, "tcp"): ("RPCbind", "Médio", "Expõe serviços RPC e facilita o mapeamento do host.", "Desativar se não houver NFS/RPC em uso."),
    (135, "tcp"): ("MSRPC", "Alto", "Serviço Windows historicamente muito explorado.", "Bloquear no firewall para redes externas."),
    (139, "tcp"): ("NetBIOS", "Alto", "Compartilhamento legado e enumeração de recursos.", "Desativar ou bloquear."),
    (143, "tcp"): ("IMAP", "Médio", "Credenciais em texto claro sem TLS.", "Usar IMAPS ou exigir STARTTLS."),
    (443, "tcp"): ("HTTPS", "Baixo", "Risco depende da versão de TLS, do certificado e da aplicação.", "Permitir só TLS 1.2 e 1.3 (ASVS 12.1.1), certificado válido e servidor atualizado."),
    (8000, "tcp"): ("HTTP local", "Médio", "Servidor HTTP temporário de demonstração, sem TLS e destinado somente ao loopback.", "Manter somente durante o laboratório e vinculado a 127.0.0.1."),
    (8001, "tcp"): ("HTTP extra", "Médio", "Servidor HTTP temporário adicional, não previsto como necessário no escopo.", "Encerrar o servidor de demonstração extra após a varredura inicial.")
    (445, "tcp"): ("SMB", "Alto", "Compartilhamento de arquivos com histórico de falhas críticas.", "Não expor; exigir SMB assinado e versões recentes."),
    (3306, "tcp"): ("MySQL", "Alto", "Banco de dados acessível pela rede.", "Escutar só em 127.0.0.1 ou em rede de serviço isolada."),
    (3389, "tcp"): ("RDP", "Alto", "Acesso remoto gráfico alvo frequente de ataques.", "Não expor; usar VPN, MFA e NLA."),
    (5432, "tcp"): ("PostgreSQL", "Alto", "Banco de dados acessível pela rede.", "Escutar só em 127.0.0.1 ou rede isolada; restringir pg_hba.conf."),
    (5900, "tcp"): ("VNC", "Alto", "Acesso gráfico remoto, muitas vezes com senha fraca.", "Não expor; tunelar por SSH."),
    (8080, "tcp"): ("HTTP-alt", "Médio", "Serviço web alternativo, muitas vezes de administração.", "Confirmar a necessidade e restringir o acesso."),
    (8443, "tcp"): ("HTTPS-alt", "Médio", "Serviço web alternativo, muitas vezes de administração.", "Confirmar a necessidade e restringir o acesso."),
}
_POR_SERVICO = {dados[0].lower(): dados for dados in CATALOGO.values()}


def buscar_catalogo(porta: int, protocolo: str, servico: str):
    dados = CATALOGO.get((porta, protocolo))
    if dados:
        return dados
    return _POR_SERVICO.get((servico or "").lower())


def risco_final(base: str, necessaria: bool) -> str:
    if not necessaria and base == "Baixo":
        return "Médio"
    return base


def classificar(portas, escopo) -> list:
    necessarios = {(s["porta"], s["protocolo"]): s["justificativa"] for s in escopo.servicos_necessarios}
    achados = []
    for p in portas:
        chave = (p.porta, p.protocolo)
        necessaria = chave in necessarios
        cat = buscar_catalogo(p.porta, p.protocolo, p.servico)
        if cat:
            nome, base, desc_risco, rec_manter = cat
        else:
            nome, base = (p.servico or "desconhecido"), "Médio"
            desc_risco = "Serviço não catalogado: não há como avaliar a necessidade sem identificá-lo."
            rec_manter = "Identificar o serviço e documentar a necessidade."
        recomendacao = (f"Manter, com endurecimento: {rec_manter}" if necessaria
                        else "Fechar: desativar o serviço e bloquear a porta no firewall.")
        achados.append({
            "porta": p.porta, "protocolo": p.protocolo, "servico": nome,
            "versao": p.produto_versao, "necessidade": "Necessária" if necessaria else "Não necessária",
            "justificativa": necessarios.get(chave, "Sem justificativa registrada"),
            "risco": risco_final(base, necessaria), "descricao_risco": desc_risco,
            "recomendacao": recomendacao,
        })
    return achados


def ausentes(portas, escopo) -> list:
    abertas = {(p.porta, p.protocolo) for p in portas}
    return [s for s in escopo.servicos_necessarios if (s["porta"], s["protocolo"]) not in abertas]


def resumo(achados) -> dict:
    return {
        "abertas": len(achados),
        "necessarias": sum(a["necessidade"] == "Necessária" for a in achados),
        "desnecessarias": sum(a["necessidade"] != "Necessária" for a in achados),
        "alto": sum(a["risco"] == "Alto" for a in achados),
        "medio": sum(a["risco"] == "Médio" for a in achados),
        "baixo": sum(a["risco"] == "Baixo" for a in achados),
        "a_fechar": [f"{a['porta']}/{a['protocolo']} ({a['servico']})"
                     for a in achados if a["necessidade"] != "Necessária"],
    }


def tabela_texto(achados) -> str:
    larguras = (9, 22, 14, 6, 46)
    cabecalho = ("PORTA", "SERVIÇO", "NECESSIDADE", "RISCO", "RECOMENDAÇÃO")

    def linha(celulas):
        colunas = [textwrap.wrap(str(c), w) or [""] for c, w in zip(celulas, larguras)]
        altura = max(len(c) for c in colunas)
        return [" | ".join((col[i] if i < len(col) else "").ljust(w) for col, w in zip(colunas, larguras))
                for i in range(altura)]

    separador = "-+-".join("-" * w for w in larguras)
    saida = linha(cabecalho) + [separador]
    for a in achados:
        saida += linha((f"{a['porta']}/{a['protocolo']}", f"{a['servico']} {a['versao']}".strip(),
                        a["necessidade"], a["risco"], a["recomendacao"]))
        saida.append(separador)
    return "\n".join(saida)


def _md(texto) -> str:
    return str(texto).replace("|", "\\|")


def tabela_markdown(achados) -> str:
    linhas = ["| Porta | Protocolo | Serviço | Necessidade | Risco | Recomendação |",
              "|---|---|---|---|---|---|"]
    for a in achados:
        linhas.append(f"| {a['porta']} | {a['protocolo']} | {_md((a['servico'] + ' ' + a['versao']).strip())} | "
                      f"{a['necessidade']} | {a['risco']} | {_md(a['recomendacao'])} |")
    return "\n".join(linhas) + "\n"


def salvar_csv(achados, caminho) -> Path:
    caminho = Path(caminho)
    caminho.parent.mkdir(parents=True, exist_ok=True)
    campos = ["porta", "protocolo", "servico", "versao", "necessidade", "justificativa",
              "risco", "descricao_risco", "recomendacao"]
    with caminho.open("w", newline="", encoding="utf-8-sig") as arq:
        escritor = csv.DictWriter(arq, fieldnames=campos)
        escritor.writeheader()
        escritor.writerows(achados)
    return caminho


def salvar_markdown(achados, caminho) -> Path:
    caminho = Path(caminho)
    caminho.parent.mkdir(parents=True, exist_ok=True)
    caminho.write_text(tabela_markdown(achados), encoding="utf-8")
    return caminho
