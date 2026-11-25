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
- varredura.py valida o escopo e executa Nmap somente contra 127.0.0.1 (loopback do próprio Windows).
- analise_portas.py compara portas abertas com os serviços necessários e gera tabelas CSV/Markdown com risco e recomendação.
- auditoria_ssh.py avalia diretivas do OpenSSH usando preferencialmente a saída efetiva de sshd -T.
- demo_e3.py exige login do banco criado por app.py, executa a varredura real quando recebe --alvo e salva evidências.
- O laboratório usa dois servidores HTTP temporários do Python (8000 necessário e 8001 extra) e o OpenSSH Server local (22).

ESCOPO E SEGURANÇA
escopo_lab.json registra responsável, finalidade, autorização, validade, rede, portas e serviços necessários. O código aceita exclusivamente 127.0.0.1/32 e rejeita qualquer outro endereço, inclusive outros IPs privados. As portas autorizadas são 22, 8000 e 8001. A porta 8001 é um serviço extra de demonstração, não necessário. Não altere esses limites para examinar a rede Wi-Fi, doméstica, acadêmica ou a Internet. Atualize a autorização somente com dados verdadeiros e válidos quando a validade vencer.

AMOSTRA OFFLINE
  py demo_e3.py
Usa arquivos fictícios em amostras/ e não executa Nmap. Não é evidência real.

LABORATÓRIO LOCAL WINDOWS
Consulte LAB_ENTREGA3.txt para instalar/preparar o OpenSSH Server, iniciar os servidores HTTP apenas em 127.0.0.1, capturar a configuração SSH e executar as varreduras antes/depois.

Varredura inicial:
  py demo_e3.py --alvo 127.0.0.1 --rotulo antes --sshd-config .\evidencias\sshd_antes.txt

Reteste:
  py demo_e3.py --alvo 127.0.0.1 --rotulo depois --sshd-config .\evidencias\sshd_depois.txt

UDP (OPCIONAL)
A demonstração principal utiliza TCP. A varredura UDP permanece opcional, exige portas explícitas e autorizadas e pode exigir privilégios elevados. O estado open|filtered é indeterminado, não uma porta aberta confirmada.

PREPARAÇÃO NO WINDOWS / POWERSHELL
Na pasta prova-si:
  py -m venv .venv
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .\.venv\Scripts\Activate.ps1
  py -m pip install -r requirements.txt
  winget install Insecure.Nmap
Feche e reabra o terminal e confira nmap --version. A Entrega 3 usa somente a biblioteca padrão do Python, sem novas dependências Python.

COMO EXECUTAR
  py app.py
Cadastre uma conta pela opção 1 antes da demonstração.
  py -m pytest -v
  py demo_e3.py --alvo 127.0.0.1 --rotulo antes --sshd-config .\evidencias\sshd_antes.txt

EVIDÊNCIAS
Guardar em evidencias/ somente saídas reais: XML do Nmap antes/depois, tabelas CSV/MD, saídas efetivas sshd_antes.txt/sshd_depois.txt, relatórios entrega3_ssh_*.txt, logs do demo_e3, testes, capturas e vídeo. Não usar os arquivos de amostras/ como evidência.

LIMITAÇÕES
- A validação do escopo é uma barreira adicional, não substitui autorização do proprietário.
- Nmap apresenta serviços acessíveis pelo loopback; Get-NetTCPConnection mostra portas locais em escuta.
- Serviço necessário não significa serviço seguro.
- A auditoria SSH é didática; prefira a saída efetiva de sshd -T, que incorpora as configurações carregadas pelo servidor.
- UDP pode ser ambíguo e exigir privilégios elevados.
- O projeto é um laboratório local, não uma ferramenta profissional de monitoramento ou auditoria.

REFERÊNCIAS
- Nmap Reference Guide: https://nmap.org/book/man.html
- Nmap NSE documentation: https://nmap.org/book/nse.html
- Microsoft Learn. OpenSSH Server installation and first use: https://learn.microsoft.com/windows-server/administration/openssh/openssh_install_firstuse
- Microsoft Learn. OpenSSH Server configuration for Windows: https://learn.microsoft.com/windows-server/administration/openssh/openssh-server-configuration
- OpenSSH sshd_config: https://man.openbsd.org/sshd_config
- OWASP Application Security Verification Standard (ASVS) 5.0.0.
- OWASP Password Storage Cheat Sheet.
- Documentação oficial Python, cryptography, argon2-cffi e sqlite3.

Repositório: https://github.com/IagoMessias/projeto-si
