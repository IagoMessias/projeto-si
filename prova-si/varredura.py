"""Entrega 3 - Escopo autorizado e varredura controlada de portas (Nmap).

Regras de segurança deste módulo:
* só varre um alvo que esteja no escopo registrado em escopo_lab.json;
* o escopo só aceita redes IPv4 PRIVADAS e pequenas (laboratório local);
* o alvo é um único endereço IP (nada de nomes de host nem faixas);
* o Nmap é chamado sem shell, com uma lista de argumentos já validados.
"""
from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

ESCOPO_PADRAO = Path(__file__).parent / "escopo_lab.json"
PASTA_EVIDENCIAS = Path(__file__).parent / "evidencias"
CAMINHOS_NMAP_WINDOWS = (
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
)
SCRIPTS_SSH = "ssh2-enum-algos,ssh-hostkey"
PREFIXO_MINIMO_IPV4 = 24
REDES_PRIVADAS_LAB = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),  # loopback: apenas para o teste local automatizado
)
TIMEOUT_NMAP = 900
CAMPOS_OBRIGATORIOS = (
    "responsavel", "finalidade", "autorizado_por", "data_autorizacao",
    "validade_ate", "redes_autorizadas", "portas", "servicos_necessarios",
)
_PORTAS = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
_ROTULO = re.compile(r"^[a-z0-9_-]{1,20}$")


class ErroEscopo(Exception):
    """Alvo ou configuração fora do escopo autorizado."""


class ErroNmap(Exception):
    """Nmap ausente, falha de execução ou saída XML inválida."""


@dataclass(frozen=True)
class Escopo:
    responsavel: str
    finalidade: str
    autorizado_por: str
    data_autorizacao: date
    validade_ate: date
    redes: tuple
    portas: str
    servicos_necessarios: tuple


@dataclass
class PortaAberta:
    host: str
    porta: int
    protocolo: str
    estado: str
    servico: str = ""
    produto: str = ""
    versao: str = ""
    extra: str = ""
    scripts: dict = field(default_factory=dict)

    @property
    def descricao(self) -> str:
        return " ".join(p for p in (self.servico, self.produto, self.versao) if p)

    @property
    def produto_versao(self) -> str:
        return " ".join(p for p in (self.produto, self.versao) if p)


@dataclass
class ResultadoVarredura:
    comando: str
    hosts_ativos: int
    portas: list
    indeterminadas: list = field(default_factory=list)


def validar_portas(portas: str) -> str:
    """Aceita só listas/intervalos numéricos como '22,80' ou '1-1024'."""
    if not isinstance(portas, str) or not _PORTAS.match(portas.strip()):
        raise ErroEscopo("Portas inválidas: use números, vírgulas e intervalos (ex.: 22,80 ou 1-1024).")
    for trecho in portas.strip().split(","):
        inicio, _, fim = trecho.partition("-")
        inicio_n, fim_n = int(inicio), int(fim or inicio)
        if not (1 <= inicio_n <= 65535 and 1 <= fim_n <= 65535 and inicio_n <= fim_n):
            raise ErroEscopo(f"Intervalo de portas inválido: {trecho}")
    return portas.strip()


def _intervalos_portas(portas: str) -> list[tuple[int, int]]:
    normalizadas = validar_portas(portas)
    intervalos = []
    for trecho in normalizadas.split(","):
        inicio, separador, fim = trecho.partition("-")
        intervalos.append((int(inicio), int(fim) if separador else int(inicio)))
    return sorted(intervalos)


def validar_portas_no_escopo(portas: str, autorizadas: str) -> str:
    """Impede que a varredura amplie as portas registradas na autorização."""
    solicitadas = _intervalos_portas(portas)
    permitidas = _intervalos_portas(autorizadas)
    for inicio, fim in solicitadas:
        proxima = inicio
        for limite_inicial, limite_final in permitidas:
            if limite_final < proxima:
                continue
            if limite_inicial > proxima:
                break
            proxima = max(proxima, limite_final + 1)
            if proxima > fim:
                break
        if proxima <= fim:
            raise ErroEscopo(
                f"Portas solicitadas ({portas}) excedem o escopo autorizado ({autorizadas}). "
                "Atualize o registro de autorização somente se a faixa maior estiver autorizada."
            )
    return validar_portas(portas)


def carregar_escopo(caminho=ESCOPO_PADRAO, hoje: date | None = None) -> Escopo:
    """Lê e valida o registro de autorização e escopo."""
    hoje = hoje or date.today()
    try:
        dados = json.loads(Path(caminho).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ErroEscopo(f"Arquivo de escopo não encontrado: {caminho}")
    except ValueError:
        raise ErroEscopo("Arquivo de escopo inválido (JSON malformado).")
    if not isinstance(dados, dict):
        raise ErroEscopo("Arquivo de escopo inválido.")
    for campo in CAMPOS_OBRIGATORIOS:
        if dados.get(campo) in (None, "", [], {}):
            raise ErroEscopo(f"Campo obrigatório ausente ou vazio no escopo: {campo}")
    try:
        autorizacao = date.fromisoformat(dados["data_autorizacao"])
        validade = date.fromisoformat(dados["validade_ate"])
    except (ValueError, TypeError):
        raise ErroEscopo("As datas do escopo devem estar no formato AAAA-MM-DD.")
    if autorizacao > hoje:
        raise ErroEscopo("A data de autorização está no futuro.")
    if validade < hoje:
        raise ErroEscopo(f"Autorização expirada em {validade.isoformat()}.")
    if not isinstance(dados["redes_autorizadas"], list):
        raise ErroEscopo("redes_autorizadas deve ser uma lista.")
    redes = []
    for texto in dados["redes_autorizadas"]:
        try:
            rede = ipaddress.ip_network(texto, strict=False)
        except (ValueError, TypeError):
            raise ErroEscopo(f"Rede inválida no escopo: {texto!r}")
        if rede.version != 4:
            raise ErroEscopo("Apenas redes IPv4 são aceitas neste laboratório.")
        if not any(rede.subnet_of(privada) for privada in REDES_PRIVADAS_LAB):
            raise ErroEscopo(f"Rede fora das faixas privadas RFC 1918 ou loopback de teste ({rede}).")
        if rede.prefixlen < PREFIXO_MINIMO_IPV4:
            raise ErroEscopo(
                f"Rede grande demais ({rede}): use prefixo /{PREFIXO_MINIMO_IPV4} ou mais específico."
            )
        redes.append(rede)
    portas = validar_portas(dados["portas"])
    necessarios = []
    if not isinstance(dados["servicos_necessarios"], list):
        raise ErroEscopo("servicos_necessarios deve ser uma lista.")
    for item in dados["servicos_necessarios"]:
        try:
            porta, proto = int(item["porta"]), str(item["protocolo"]).lower()
            justificativa = str(item["justificativa"]).strip()
        except (KeyError, TypeError, ValueError):
            raise ErroEscopo("Cada serviço necessário precisa de porta, protocolo e justificativa.")
        if not (1 <= porta <= 65535) or proto not in ("tcp", "udp") or not justificativa:
            raise ErroEscopo(f"Serviço necessário inválido: {item!r}")
        validar_portas_no_escopo(str(porta), portas)
        necessarios.append({"porta": porta, "protocolo": proto, "justificativa": justificativa})
    return Escopo(
        responsavel=str(dados["responsavel"]), finalidade=str(dados["finalidade"]),
        autorizado_por=str(dados["autorizado_por"]), data_autorizacao=autorizacao,
        validade_ate=validade, redes=tuple(redes), portas=portas,
        servicos_necessarios=tuple(necessarios),
    )


def validar_alvo(alvo: str, escopo: Escopo):
    """Retorna o IP se estiver no escopo; caso contrário levanta ErroEscopo."""
    if not isinstance(alvo, str):
        raise ErroEscopo("O alvo deve ser texto.")
    try:
        ip = ipaddress.ip_address(alvo.strip())
    except ValueError:
        raise ErroEscopo("Alvo inválido: informe um único endereço IP (nomes de host e faixas não são aceitos).")
    if ip.version != 4:
        raise ErroEscopo("Apenas alvos IPv4 são aceitos neste laboratório.")
    if not any(ip in rede for rede in escopo.redes):
        redes = ", ".join(str(r) for r in escopo.redes)
        raise ErroEscopo(f"Alvo {ip} fora do escopo autorizado ({redes}).")
    return ip


def localizar_nmap() -> str:
    caminho = shutil.which("nmap")
    if caminho:
        return caminho
    for candidato in CAMINHOS_NMAP_WINDOWS:
        if Path(candidato).exists():
            return candidato
    raise ErroNmap("Nmap não encontrado. No Windows: winget install Insecure.Nmap (e reabra o terminal).")


def montar_comando(alvo, portas: str, xml_saida, nmap: str = "nmap",
                   udp: bool = False, scripts_ssh: bool = True, sem_ping: bool = False) -> list:
    """Monta a lista de argumentos (sem shell).
    TCP: -sT + -sV; UDP: -sU somente nas portas autorizadas selecionadas.
    """
    cmd = [nmap]
    if udp:
        cmd += ["-sU", "-p", validar_portas(portas)]
    else:
        cmd += ["-sT", "-sV", "-p", validar_portas(portas)]
    cmd += ["--open", "-T3"]
    if sem_ping:
        cmd.append("-Pn")
    if scripts_ssh and not udp:
        cmd += ["--script", SCRIPTS_SSH]
    cmd += ["-oX", str(xml_saida), str(alvo)]
    return cmd


def executar_nmap(alvo: str, escopo: Escopo, portas: str | None = None, udp: bool = False,
                  rotulo: str = "antes", pasta_saida=PASTA_EVIDENCIAS):
    """Valida alvo/faixa, executa Nmap e devolve (caminho XML, comando em texto)."""
    ip = validar_alvo(alvo, escopo)
    if not _ROTULO.match(rotulo):
        raise ErroEscopo("Rótulo inválido: use letras minúsculas, números, hífen ou sublinhado.")
    portas_efetivas = validar_portas_no_escopo(portas or escopo.portas, escopo.portas)
    nmap = localizar_nmap()
    pasta = Path(pasta_saida)
    pasta.mkdir(parents=True, exist_ok=True)
    xml = pasta / f"nmap_{rotulo}_{str(ip).replace('.', '-')}_{'udp' if udp else 'tcp'}.xml"
    cmd = montar_comando(ip, portas_efetivas, xml, nmap=nmap, udp=udp)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_NMAP, check=False)
    except subprocess.TimeoutExpired:
        raise ErroNmap(f"O Nmap excedeu {TIMEOUT_NMAP} s e foi interrompido.")
    except OSError as erro:
        raise ErroNmap(f"Não foi possível iniciar o Nmap: {erro}")
    if proc.returncode != 0:
        raise ErroNmap((proc.stderr or proc.stdout or "Falha desconhecida do Nmap.").strip()[:400])
    return xml, subprocess.list2cmdline(cmd)


def ler_xml(caminho) -> ResultadoVarredura:
    """Converte o XML do Nmap; separa abertas confirmadas de estados indeterminados."""
    try:
        raiz = ET.parse(str(caminho)).getroot()
    except (ET.ParseError, OSError) as erro:
        raise ErroNmap(f"XML do Nmap inválido ou ausente: {erro}")
    if raiz.tag != "nmaprun":
        raise ErroNmap("O arquivo não é uma saída XML do Nmap.")
    portas, indeterminadas, ativos = [], [], 0
    for host in raiz.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ativos += 1
        endereco = host.find("address[@addrtype='ipv4']")
        ip = endereco.get("addr", "") if endereco is not None else ""
        for p in host.findall("ports/port"):
            estado_el = p.find("state")
            estado = estado_el.get("state", "") if estado_el is not None else ""
            if estado not in ("open", "open|filtered"):
                continue
            try:
                numero = int(p.get("portid", ""))
            except ValueError:
                continue
            svc = p.find("service")
            detectada = PortaAberta(
                host=ip, porta=numero, protocolo=p.get("protocol", ""), estado=estado,
                servico=svc.get("name", "") if svc is not None else "",
                produto=svc.get("product", "") if svc is not None else "",
                versao=svc.get("version", "") if svc is not None else "",
                extra=svc.get("extrainfo", "") if svc is not None else "",
                scripts={s.get("id", ""): s.get("output", "") for s in p.findall("script")},
            )
            if estado == "open":
                portas.append(detectada)
            else:
                indeterminadas.append(detectada)
    portas.sort(key=lambda x: (x.protocolo, x.porta))
    indeterminadas.sort(key=lambda x: (x.protocolo, x.porta))
    return ResultadoVarredura(
        comando=raiz.get("args", ""), hosts_ativos=ativos,
        portas=portas, indeterminadas=indeterminadas,
    )
