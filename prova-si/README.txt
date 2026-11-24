PROJETO INTEGRADOR - SEGURANÇA APLICADA AO DESENVOLVIMENTO
Projeto Integrador - Segurança da Informação - Unit

ENTREGA 1 - CRIPTOGRAFIA HÍBRIDA E ASSINATURA DIGITAL
- AES-256-GCM cifra o conteúdo.
- RSA-OAEP (3072 bits, SHA-256) protege a chave AES.
- Ed25519 assina o envelope.
- O destino verifica a assinatura antes de decifrar.

ENTREGA 2 - HASH E AUTENTICAÇÃO SEGURA
- Argon2id, com salt aleatório, protege senhas.
- SQLite armazena usuário e hash, nunca a senha em texto puro.
- A aplicação app.py permite cadastrar e autenticar usuários.

ENTREGA 3 - VARREDURA, SERVIÇOS E SSH
- varredura.py valida o registro de autorização e executa Nmap para um único IP IPv4 dentro da rede privada autorizada.
- analise_portas.py compara as portas abertas com os serviços necessários e gera risco/recomendação em tabela CSV e Markdown.
- auditoria_ssh.py avalia diretivas importantes do OpenSSH, preferencialmente usando a saída efetiva de sshd -T.
- demo_e3.py exige login do mesmo banco criado por app.py e apresenta a demonstração offline ou executa uma varredura real quando recebe --alvo.

ESCOPO E SEGURANÇA
O arquivo escopo_lab.json define responsável, finalidade, autorização, validade, rede autorizada, faixa de portas e serviços necessários. O programa recusa hostnames, IPs fora do escopo e portas que ampliem a faixa autorizada. Use somente a VM própria do laboratório em rede Host-only. O arquivo atual autoriza 192.168.56.0/24 e portas 1-1024, com validade até 2026-12-02; confirme a autorização e atualize os dados de forma verdadeira antes de realizar uma atividade após a validade.

AMOSTRA OFFLINE
  py demo_e3.py
Usa arquivos fictícios em amostras/ e não executa Nmap. As tabelas produzidas ficam em amostras/saidas/ e não são evidência da VM.

VARREDURA REAL DA VM
  py demo_e3.py --alvo 192.168.56.101 --rotulo antes
O IP é ilustrativo. Use somente o IP Host-only real da sua VM, dentro da rede registrada em escopo_lab.json. Para restringir a uma seleção, use --portas 22,80. A seleção deve ser subconjunto da faixa autorizada.

RETESTE
  py demo_e3.py --alvo 192.168.56.101 --rotulo depois --sshd-config evidencias\sshd_depois.txt

UDP (OPCIONAL)
  py demo_e3.py --alvo 192.168.56.101 --udp --portas 53,123,161 --rotulo antes_udp
Exige terminal elevado e portas UDP explicitamente selecionadas e autorizadas. O estado open|filtered é indeterminado, não uma porta aberta confirmada.

PREPARAÇÃO NO WINDOWS / POWERSHELL
Na pasta prova-si:
  py -m venv .venv
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .\.venv\Scripts\Activate.ps1
  py -m pip install -r requirements.txt
  winget install Insecure.Nmap
Feche e reabra o terminal e confira nmap --version. A Entrega 3 usa módulos da biblioteca padrão do Python; não exige dependências Python adicionais.

COMO EXECUTAR
  py app.py
Cadastre uma conta pela opção 1 antes da demonstração.
  py -m pytest -v
  py demo_e3.py
  py demo_e3.py --alvo IP_DA_VM --rotulo antes

O passo a passo da VM, serviços de teste, coleta interna com ss -tulpn, hardening do SSH, firewall e reteste está em LAB_ENTREGA3.txt.

EVIDÊNCIAS
Guardar em evidencias/ apenas saídas reais do laboratório: XML do Nmap antes/depois, tabelas CSV/MD, ss_antes.txt/ss_depois.txt, sshd_antes.txt/sshd_depois.txt, logs de execução, testes, capturas e vídeo. Não copiar arquivos da pasta amostras como evidência.

LIMITAÇÕES
- A validação do escopo é uma barreira adicional e não substitui autorização do proprietário do alvo.
- Nmap mostra o que está alcançável pela rede; ss mostra o que está escutando internamente.
- Serviço necessário não significa serviço seguro.
- A auditoria SSH é didática. O parser simples sinaliza Include e Match; prefira a saída efetiva de sshd -T e use sshd -T -C para condições específicas.
- UDP pode ser ambíguo e exigir privilégios elevados.
- O projeto é um laboratório local, não uma ferramenta de monitoramento ou auditoria profissional.

REFERÊNCIAS
- Nmap Reference Guide: https://nmap.org/book/man.html
- Nmap NSE documentation: https://nmap.org/book/nse.html
- OpenSSH sshd_config: https://man.openbsd.org/sshd_config
- OpenSSH sshd(8): https://man.openbsd.org/sshd
- OWASP Application Security Verification Standard (ASVS) 5.0.0.
- OWASP Password Storage Cheat Sheet.
- Documentação oficial Python, cryptography, argon2-cffi e sqlite3.

Repositório: https://github.com/IagoMessias/projeto-si
