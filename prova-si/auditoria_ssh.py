"""Entrega 3 - Auditoria da configuração do servidor SSH.

Lê sshd_config ou, preferencialmente, a saída efetiva de 'sudo sshd -T'.
Diretivas Include e blocos Match são sinalizados, mas não expandidos pelo parser.
"""
from __future__ import annotations

from pathlib import Path

PADROES = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "pubkeyauthentication": "yes",
    "permitemptypasswords": "no",
    "kbdinteractiveauthentication": "yes",
    "maxauthtries": "6",
    "logingracetime": "120",
    "x11forwarding": "no",
    "clientaliveinterval": "0",
    "loglevel": "info",
    "port": "22",
}


def _segundos(valor: str):
    valor = valor.strip().lower()
    multiplicadores = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    try:
        if valor[-1:] in multiplicadores:
            return int(valor[:-1]) * multiplicadores[valor[-1]]
        return int(valor)
    except (ValueError, IndexError):
        return None


def ler_configuracao(texto: str):
    """Lê diretivas globais e sinaliza Include/Match (não os expande)."""
    cfg, usou_match, usou_include = {}, False, False
    for bruta in texto.splitlines():
        linha = bruta.split("#", 1)[0].strip()
        if not linha:
            continue
        partes = linha.split(None, 1)
        chave = partes[0].lower()
        valor = partes[1].strip().lower() if len(partes) > 1 else ""
        if chave == "match":
            usou_match = True
            break
        if chave == "include":
            usou_include = True
            continue
        cfg.setdefault(chave, []).append(valor)
    return cfg, usou_match, usou_include


def auditar(texto: str) -> list:
    cfg, usou_match, usou_include = ler_configuracao(texto)

    def obter(chave: str):
        if chave in cfg:
            return cfg[chave][0], False
        return PADROES.get(chave, ""), True

    achados = []

    def adicionar(nome, atual, padrao, esperado, status, recomendacao, controle):
        achados.append({
            "diretiva": nome,
            "atual": f"{atual or '(não definido)'}{' (padrão)' if padrao else ''}",
            "esperado": esperado, "status": status,
            "recomendacao": recomendacao, "controle": controle,
        })

    v, pad = obter("permitrootlogin")
    status = "OK" if v == "no" else (
        "ATENÇÃO" if v in ("prohibit-password", "without-password", "forced-commands-only") else "FALHA"
    )
    adicionar("PermitRootLogin", v, pad, "no", status,
              "Proibir login direto como root; usar usuário comum e sudo.", "ISO 27002 8.5")

    v, pad = obter("passwordauthentication")
    adicionar("PasswordAuthentication", v, pad, "no", "OK" if v == "no" else "FALHA",
              "Desativar senha e usar chaves (depois de confirmar que o login por chave funciona).",
              "ISO 27002 8.5 / 5.17")

    v, pad = obter("pubkeyauthentication")
    adicionar("PubkeyAuthentication", v, pad, "yes", "OK" if v == "yes" else "FALHA",
              "Manter a autenticação por chave pública habilitada.", "ISO 27002 8.5")

    v, pad = obter("permitemptypasswords")
    adicionar("PermitEmptyPasswords", v, pad, "no", "OK" if v == "no" else "FALHA",
              "Nunca aceitar contas com senha vazia.", "ISO 27002 5.17")

    chave_kbd = ("challengeresponseauthentication"
                 if "challengeresponseauthentication" in cfg and "kbdinteractiveauthentication" not in cfg
                 else "kbdinteractiveauthentication")
    v, pad = obter(chave_kbd)
    adicionar("KbdInteractiveAuthentication", v, pad, "no", "OK" if v == "no" else "ATENÇÃO",
              "Desativar: com PAM ele pode reabrir a autenticação por senha.", "ISO 27002 8.5")

    v, pad = obter("maxauthtries")
    try:
        tentativas = int(v)
        status = "OK" if 1 <= tentativas <= 4 else "ATENÇÃO"
    except ValueError:
        status = "ATENÇÃO"
    adicionar("MaxAuthTries", v, pad, "4 ou menos", status,
              "Reduzir as tentativas por conexão (ex.: 3) para dificultar força bruta.", "ISO 27002 8.5")

    v, pad = obter("logingracetime")
    seg = _segundos(v)
    adicionar("LoginGraceTime", v, pad, "entre 1 e 60 s",
              "OK" if seg is not None and 1 <= seg <= 60 else "ATENÇÃO",
              "Reduzir o tempo para concluir o login (ex.: 30 s).", "ISO 27002 8.5")

    usuarios_grupos = cfg.get("allowusers", []) + cfg.get("allowgroups", [])
    restrito = any(valor.strip() for valor in usuarios_grupos)
    adicionar("AllowUsers / AllowGroups", ", ".join(usuarios_grupos), False, "definido",
              "OK" if restrito else "ATENÇÃO",
              "Listar explicitamente quem pode entrar por SSH.", "ISO 27002 8.5 / 8.20")

    v, pad = obter("x11forwarding")
    adicionar("X11Forwarding", v, pad, "no", "OK" if v == "no" else "ATENÇÃO",
              "Desativar o encaminhamento gráfico se não for usado.", "ISO 27002 8.9")

    v, pad = obter("clientaliveinterval")
    seg = _segundos(v)
    adicionar("ClientAliveInterval", v, pad, "maior que 0",
              "OK" if seg is not None and seg > 0 else "ATENÇÃO",
              "Definir limite de inatividade para encerrar sessões abandonadas.", "ISO 27002 8.5")

    v, pad = obter("loglevel")
    adicionar("LogLevel", v, pad, "info ou verbose", "OK" if v in ("info", "verbose") else "ATENÇÃO",
              "Registrar tentativas e falhas de autenticação.", "ISO 27002 8.15")

    v, pad = obter("port")
    adicionar("Port", v, pad, "informativo", "INFO",
              "Mudar a porta não substitui os controles acima (apenas reduz ruído de varreduras).",
              "ISO 27002 8.20")

    if usou_include:
        adicionar("Include", "presente", False, "avaliar configuração efetiva", "INFO",
                  "O parser não lê arquivos incluídos; prefira a saída de 'sudo sshd -T' no host.",
                  "ISO 27002 8.9")
    if usou_match:
        adicionar("Match", "presente", False, "revisar à mão", "INFO",
                  "Blocos Match não foram avaliados; use 'sshd -T -C' para um contexto específico.",
                  "ISO 27002 8.9")
    return achados


def auditar_arquivo(caminho) -> list:
    return auditar(Path(caminho).read_text(encoding="utf-8", errors="replace"))


def resumo(achados) -> dict:
    contagem = {"OK": 0, "ATENÇÃO": 0, "FALHA": 0, "INFO": 0}
    for achado in achados:
        contagem[achado["status"]] += 1
    return contagem


def tabela_texto(achados) -> str:
    larguras = (28, 22, 15, 8)
    cab = ("DIRETIVA", "ATUAL", "ESPERADO", "STATUS")
    linhas = [" | ".join(c.ljust(w) for c, w in zip(cab, larguras)),
              "-+-".join("-" * w for w in larguras)]
    for achado in achados:
        linhas.append(" | ".join(str(c)[:w].ljust(w) for c, w in zip(
            (achado["diretiva"], achado["atual"], achado["esperado"], achado["status"]), larguras
        )))
    return "\n".join(linhas)
