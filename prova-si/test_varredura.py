"""Testes da Entrega 3: escopo, Nmap, classificação de portas e auditoria SSH."""

import json
import socket
import threading
from datetime import date
from pathlib import Path

import pytest

import analise_portas as ap
import auditoria_ssh as ssh
import varredura as vr

AMOSTRAS = Path(__file__).parent / "amostras"
HOJE = date(2026, 11, 22)

ESCOPO_VALIDO = {
    "responsavel": "Aluno", "finalidade": "Teste", "autorizado_por": "Aluno",
    "data_autorizacao": "2026-11-20", "validade_ate": "2026-12-02",
    "redes_autorizadas": ["192.168.56.0/24"], "portas": "1-1024",
    "servicos_necessarios": [
        {"porta": 22, "protocolo": "tcp", "justificativa": "SSH"},
        {"porta": 80, "protocolo": "tcp", "justificativa": "Web"},
    ],
}


def _escopo(tmp_path, **mudancas):
    dados = {**ESCOPO_VALIDO, **mudancas}
    arquivo = tmp_path / "escopo.json"
    arquivo.write_text(json.dumps(dados), encoding="utf-8")
    return arquivo


@pytest.fixture
def escopo(tmp_path):
    return vr.carregar_escopo(_escopo(tmp_path), hoje=HOJE)


# Escopo e autorização
def test_escopo_valido_e_carregado(escopo):
    assert str(escopo.redes[0]) == "192.168.56.0/24"
    assert escopo.validade_ate == date(2026, 12, 2)


def test_escopo_real_do_projeto_e_valido():
    assert vr.carregar_escopo(hoje=HOJE).servicos_necessarios


@pytest.mark.parametrize("campo", list(vr.CAMPOS_OBRIGATORIOS))
def test_campo_obrigatorio_ausente_e_rejeitado(tmp_path, campo):
    dados = dict(ESCOPO_VALIDO)
    del dados[campo]
    arquivo = tmp_path / "e.json"
    arquivo.write_text(json.dumps(dados), encoding="utf-8")
    with pytest.raises(vr.ErroEscopo):
        vr.carregar_escopo(arquivo, hoje=HOJE)


def test_autorizacao_expirada_e_rejeitada(tmp_path):
    with pytest.raises(vr.ErroEscopo, match="expirada"):
        vr.carregar_escopo(_escopo(tmp_path, validade_ate="2026-11-01"), hoje=HOJE)


def test_autorizacao_com_data_futura_e_rejeitada(tmp_path):
    with pytest.raises(vr.ErroEscopo, match="futuro"):
        vr.carregar_escopo(_escopo(tmp_path, data_autorizacao="2026-12-01"), hoje=HOJE)


@pytest.mark.parametrize(
    "rede",
    ["8.8.8.0/24", "0.0.0.0/0", "10.0.0.0/8", "203.0.113.0/24",
     "100.64.0.0/24", "2001:db8::/64", "nao-e-rede"],
)
def test_rede_publica_grande_ou_invalida_e_rejeitada(tmp_path, rede):
    with pytest.raises(vr.ErroEscopo):
        vr.carregar_escopo(_escopo(tmp_path, redes_autorizadas=[rede]), hoje=HOJE)


def test_arquivo_ausente_ou_malformado(tmp_path):
    with pytest.raises(vr.ErroEscopo):
        vr.carregar_escopo(tmp_path / "nao_existe.json", hoje=HOJE)
    ruim = tmp_path / "ruim.json"
    ruim.write_text("{nao e json", encoding="utf-8")
    with pytest.raises(vr.ErroEscopo):
        vr.carregar_escopo(ruim, hoje=HOJE)


def test_alvo_no_escopo_e_aceito(escopo):
    assert str(vr.validar_alvo("192.168.56.101", escopo)) == "192.168.56.101"


@pytest.mark.parametrize("alvo", [
    "8.8.8.8", "192.168.1.10", "scanme.nmap.org", "192.168.56.0/24",
    "192.168.56.101; calc", "192.168.56.101 -p-", "", "::1", None,
])
def test_alvo_fora_do_escopo_ou_malformado_e_rejeitado(escopo, alvo):
    with pytest.raises(vr.ErroEscopo):
        vr.validar_alvo(alvo, escopo)


# Validação das portas e comando Nmap
@pytest.mark.parametrize("portas", ["22", "22,80,443", "1-1024", "1-100,8080"])
def test_portas_validas(portas):
    assert vr.validar_portas(portas) == portas


def test_portas_especificas_dentro_do_escopo_sao_aceitas():
    assert vr.validar_portas_no_escopo("22,80", "1-1024") == "22,80"


@pytest.mark.parametrize("solicitadas", ["1-65535", "1024-1025", "3306", "22,3306"])
def test_portas_fora_do_escopo_sao_rejeitadas(solicitadas):
    with pytest.raises(vr.ErroEscopo, match="excedem o escopo"):
        vr.validar_portas_no_escopo(solicitadas, "1-1024")


@pytest.mark.parametrize("portas", ["", "0", "70000", "100-50", "22;ls", "22, 80", "a-b", "1-1024 -A"])
def test_portas_invalidas(portas):
    with pytest.raises(vr.ErroEscopo):
        vr.validar_portas(portas)


def test_comando_tcp_e_uma_lista_sem_shell(tmp_path):
    cmd = vr.montar_comando("192.168.56.101", "1-1024", tmp_path / "s.xml")
    assert isinstance(cmd, list)
    assert cmd[0] == "nmap" and "-sT" in cmd and "-sV" in cmd and "-oX" in cmd
    assert cmd[-1] == "192.168.56.101"
    assert cmd[cmd.index("-p") + 1] == "1-1024"
    assert "-A" not in cmd and "-sS" not in cmd


def test_comando_udp_respeita_a_faixa_informada(tmp_path):
    cmd = vr.montar_comando("192.168.56.101", "53,123,161", tmp_path / "s.xml", udp=True)
    assert "-sU" in cmd and "-p" in cmd
    assert cmd[cmd.index("-p") + 1] == "53,123,161"
    assert "--top-ports" not in cmd and "-sV" not in cmd


def test_comando_rejeita_portas_maliciosas(tmp_path):
    with pytest.raises(vr.ErroEscopo):
        vr.montar_comando("192.168.56.101", "22; calc", tmp_path / "s.xml")


def test_executar_nmap_recusa_alvo_fora_do_escopo_antes_de_rodar(escopo, tmp_path):
    with pytest.raises(vr.ErroEscopo):
        vr.executar_nmap("8.8.8.8", escopo, pasta_saida=tmp_path)
    assert not list(tmp_path.glob("*.xml"))


def test_varredura_udp_exige_portas_explicitas(escopo, tmp_path):
    with pytest.raises(vr.ErroEscopo, match="exige --portas explícito"):
        vr.executar_nmap("192.168.56.101", escopo, udp=True, pasta_saida=tmp_path)
    assert not list(tmp_path.glob("*.xml"))


def test_executar_nmap_recusa_ampliacao_de_portas_antes_de_rodar(escopo, tmp_path):
    with pytest.raises(vr.ErroEscopo, match="excedem o escopo"):
        vr.executar_nmap("192.168.56.101", escopo, portas="1-65535", pasta_saida=tmp_path)
    assert not list(tmp_path.glob("*.xml"))


def test_escopo_rejeita_servico_necessario_fora_da_faixa(tmp_path):
    servicos = [
        {"porta": 22, "protocolo": "tcp", "justificativa": "SSH"},
        {"porta": 3306, "protocolo": "tcp", "justificativa": "Banco"},
    ]
    with pytest.raises(vr.ErroEscopo):
        vr.carregar_escopo(_escopo(tmp_path, servicos_necessarios=servicos, portas="1-1024"), hoje=HOJE)


def test_rotulo_invalido_e_rejeitado(escopo, tmp_path):
    with pytest.raises(vr.ErroEscopo):
        vr.executar_nmap("192.168.56.101", escopo, rotulo="../fora", pasta_saida=tmp_path)


# Leitura do XML
def test_ler_xml_de_amostra():
    resultado = vr.ler_xml(AMOSTRAS / "nmap_lab_exemplo.xml")
    assert resultado.hosts_ativos == 1
    assert [p.porta for p in resultado.portas] == [21, 22, 80, 111]
    ssh_port = next(p for p in resultado.portas if p.porta == 22)
    assert ssh_port.produto == "OpenSSH" and "ssh-hostkey" in ssh_port.scripts


def test_ler_xml_separa_estado_open_filtered(tmp_path):
    arquivo = tmp_path / "udp.xml"
    arquivo.write_text(
        '<nmaprun><host><status state="up"/><address addr="192.168.56.101" addrtype="ipv4"/>'
        '<ports><port protocol="udp" portid="53"><state state="open|filtered"/></port></ports></host></nmaprun>',
        encoding="utf-8",
    )
    resultado = vr.ler_xml(arquivo)
    assert resultado.portas == []
    assert len(resultado.indeterminadas) == 1
    assert resultado.indeterminadas[0].estado == "open|filtered"


def test_ler_xml_invalido(tmp_path):
    ruim = tmp_path / "x.xml"
    ruim.write_text("isto nao e xml", encoding="utf-8")
    with pytest.raises(vr.ErroNmap):
        vr.ler_xml(ruim)
    outro = tmp_path / "y.xml"
    outro.write_text("<outracoisa/>", encoding="utf-8")
    with pytest.raises(vr.ErroNmap):
        vr.ler_xml(outro)
    with pytest.raises(vr.ErroNmap):
        vr.ler_xml(tmp_path / "nao_existe.xml")


# Classificação e saídas
def test_classificacao_necessidade_e_risco(escopo):
    achados = {
        a["porta"]: a
        for a in ap.classificar(vr.ler_xml(AMOSTRAS / "nmap_lab_exemplo.xml").portas, escopo)
    }
    assert achados[21]["necessidade"] == "Não necessária" and achados[21]["risco"] == "Alto"
    assert achados[21]["recomendacao"].startswith("Fechar")
    assert achados[22]["necessidade"] == "Necessária"
    assert achados[22]["recomendacao"].startswith("Manter")
    assert achados[111]["necessidade"] == "Não necessária"


def test_servico_desnecessario_nunca_fica_com_risco_baixo():
    assert ap.risco_final("Baixo", necessaria=False) == "Médio"
    assert ap.risco_final("Baixo", necessaria=True) == "Baixo"
    assert ap.risco_final("Alto", necessaria=True) == "Alto"


def test_servico_desconhecido_tem_risco_medio(escopo):
    porta = vr.PortaAberta(host="192.168.56.101", porta=9999, protocolo="tcp", estado="open", servico="abc")
    achado = ap.classificar([porta], escopo)[0]
    assert achado["risco"] == "Médio" and "não catalogado" in achado["descricao_risco"]


def test_servico_em_porta_nao_padrao_e_reconhecido_pelo_nome(escopo):
    porta = vr.PortaAberta(host="h", porta=2121, protocolo="tcp", estado="open", servico="ftp")
    assert ap.classificar([porta], escopo)[0]["risco"] == "Alto"


def test_servico_necessario_ausente_e_listado(escopo):
    portas = vr.ler_xml(AMOSTRAS / "nmap_lab_exemplo.xml").portas
    assert ap.ausentes(portas, escopo) == []
    assert [s["porta"] for s in ap.ausentes([p for p in portas if p.porta != 80], escopo)] == [80]


def test_resumo_conta_portas_a_fechar(escopo):
    achados = ap.classificar(vr.ler_xml(AMOSTRAS / "nmap_lab_exemplo.xml").portas, escopo)
    resumo = ap.resumo(achados)
    assert resumo["abertas"] == 4 and resumo["necessarias"] == 2 and resumo["desnecessarias"] == 2
    assert "21/tcp (FTP)" in resumo["a_fechar"]


def test_tabelas_markdown_e_csv(escopo, tmp_path):
    achados = ap.classificar(vr.ler_xml(AMOSTRAS / "nmap_lab_exemplo.xml").portas, escopo)
    assert ap.tabela_markdown(achados).startswith(
        "| Porta | Protocolo | Serviço | Necessidade | Risco | Recomendação |"
    )
    csv_ = ap.salvar_csv(achados, tmp_path / "t.csv")
    assert csv_.read_text(encoding="utf-8-sig").splitlines()[0].startswith("porta,protocolo,servico")
    assert "21/tcp" in ap.tabela_texto(achados)


# Auditoria SSH
def _por_diretiva(achados):
    return {achado["diretiva"]: achado for achado in achados}


def test_ssh_configuracao_fraca_tem_falhas():
    d = _por_diretiva(ssh.auditar_arquivo(AMOSTRAS / "sshd_config_inseguro.conf"))
    assert d["PermitRootLogin"]["status"] == "FALHA"
    assert d["PasswordAuthentication"]["status"] == "FALHA"
    assert d["X11Forwarding"]["status"] == "ATENÇÃO"
    assert d["AllowUsers / AllowGroups"]["status"] == "ATENÇÃO"


def test_ssh_configuracao_endurecida_nao_tem_falha_nem_atencao():
    resumo = ssh.resumo(ssh.auditar_arquivo(AMOSTRAS / "sshd_config_endurecido.conf"))
    assert resumo["FALHA"] == 0 and resumo["ATENÇÃO"] == 0


def test_ssh_diretivas_ausentes_usam_padrao_do_openssh():
    d = _por_diretiva(ssh.auditar(""))
    assert d["PasswordAuthentication"]["status"] == "FALHA"
    assert "(padrão)" in d["PasswordAuthentication"]["atual"]
    assert d["PermitRootLogin"]["status"] == "ATENÇÃO"


def test_ssh_aceita_saida_do_sshd_T_em_minusculas():
    texto = "permitrootlogin no\npasswordauthentication no\nallowusers aluno\nmaxauthtries 3\n"
    d = _por_diretiva(ssh.auditar(texto))
    assert d["PermitRootLogin"]["status"] == "OK" and d["MaxAuthTries"]["status"] == "OK"


def test_ssh_primeiro_valor_vale_e_comentarios_sao_ignorados():
    d = _por_diretiva(ssh.auditar("PasswordAuthentication no  # seguro\nPasswordAuthentication yes\n"))
    assert d["PasswordAuthentication"]["status"] == "OK"
    d = _por_diretiva(ssh.auditar("#PasswordAuthentication no\n"))
    assert d["PasswordAuthentication"]["status"] == "FALHA"


def test_ssh_bloco_match_e_ignorado_e_sinalizado():
    achados = ssh.auditar("PasswordAuthentication no\nMatch User teste\n  PasswordAuthentication yes\n")
    d = _por_diretiva(achados)
    assert d["PasswordAuthentication"]["status"] == "OK" and d["Match"]["status"] == "INFO"


def test_ssh_allowusers_vazio_nao_e_considerado_restricao():
    d = _por_diretiva(ssh.auditar("AllowUsers\nPasswordAuthentication no\n"))
    assert d["AllowUsers / AllowGroups"]["status"] == "ATENÇÃO"


def test_ssh_include_e_sinalizado_para_usar_sshd_T():
    d = _por_diretiva(ssh.auditar("Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n"))
    assert d["Include"]["status"] == "INFO"
    assert "sshd -T" in d["Include"]["recomendacao"]


# Integração real local: só executa quando o Nmap está instalado
def _nmap_disponivel():
    try:
        vr.localizar_nmap()
        return True
    except vr.ErroNmap:
        return False


@pytest.mark.skipif(not _nmap_disponivel(), reason="Nmap não instalado")
def test_varredura_real_em_loopback(tmp_path):
    servidor = socket.socket()
    servidor.bind(("127.0.0.1", 0))
    servidor.listen(5)
    porta = servidor.getsockname()[1]
    ativo = True

    def aceitar():
        servidor.settimeout(0.5)
        while ativo:
            try:
                conexao, _ = servidor.accept()
                conexao.close()
            except OSError:
                pass

    fio = threading.Thread(target=aceitar, daemon=True)
    fio.start()
    try:
        arquivo = tmp_path / "e.json"
        arquivo.write_text(
            json.dumps({
                **ESCOPO_VALIDO,
                "redes_autorizadas": ["127.0.0.0/24"],
                "portas": str(porta),
                "servicos_necessarios": [
                    {"porta": porta, "protocolo": "tcp", "justificativa": "teste"}
                ],
            }),
            encoding="utf-8",
        )
        escopo = vr.carregar_escopo(arquivo, hoje=HOJE)
        xml, comando = vr.executar_nmap(
            "127.0.0.1", escopo, portas=str(porta), rotulo="teste", pasta_saida=tmp_path
        )
        resultado = vr.ler_xml(xml)
        assert porta in [p.porta for p in resultado.portas]
        assert "nmap" in comando.lower()
    finally:
        ativo = False
        fio.join(timeout=2)
        servidor.close()
