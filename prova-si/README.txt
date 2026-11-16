PROJETO INTEGRADOR - SEGURANÇA APLICADA AO DESENVOLVIMENTO
Projeto Integrador - Segurança da Informação - Unit

OBJETIVO
Aplicação didática que reúne os mecanismos de segurança desenvolvidos nas entregas progressivas do projeto.

ENTREGA 1 - CRIPTOGRAFIA ASSIMÉTRICA E CONFIANÇA
O QUE FAZ
Protege uma mensagem enviada a outro serviço e permite ao destino verificar quem a enviou. Usa cifragem híbrida (sigilo) e assinatura digital (autenticidade), com a biblioteca cryptography.

COMO FUNCIONA
1. O remetente cifra a mensagem com AES-256-GCM.
2. A chave AES é protegida com RSA-OAEP usando a chave pública do destino.
3. O remetente assina o envelope com Ed25519.
4. O destino verifica a assinatura e só depois decifra.

ALGORITMOS E PARÂMETROS
- RSA-OAEP: 3072 bits, e = 65537, SHA-256.
- AES-256-GCM: nonce de 96 bits aleatório por mensagem, tag de 128 bits.
- Ed25519: assinatura digital do envelope.
- Chaves privadas em PEM PKCS#8 protegidas por senha.

ENTREGA 2 - HASH E AUTENTICAÇÃO SEGURA
O QUE FAZ
Permite cadastrar usuários e fazer login sem armazenar senhas em texto puro.

COMO FUNCIONA
1. No cadastro, a aplicação valida o nome de usuário e a senha.
2. Argon2id gera um hash com salt aleatório.
3. O banco SQLite armazena o nome de usuário e o hash codificado.
4. No login, a biblioteca Argon2 verifica a senha informada contra o hash armazenado.

ARGON2ID E PARÂMETROS
- Algoritmo: Argon2id, pela biblioteca argon2-cffi.
- Memória: 47.104 KiB (46 MiB).
- Iterações (time_cost): 1.
- Paralelismo: 1.
- Salt aleatório: 16 bytes, gerado pela biblioteca.
- Tamanho do hash: 32 bytes.
- Senha: mínimo de 8 caracteres; não há exigência de composição por maiúsculas, números ou símbolos.
- A string PHC produzida pela biblioteca contém algoritmo, parâmetros, salt e hash. Por isso, o salt não precisa de coluna separada no SQLite.

POR QUE NÃO USAR SHA-256 ISOLADAMENTE PARA SENHAS
SHA-256 é uma função de hash rápida e de uso geral. Essa rapidez permite que um atacante teste muitas senhas por segundo após obter uma cópia do banco. Argon2id é uma função específica para senhas, com custo configurável de memória e tempo, tornando cada tentativa mais cara. O salt aleatório e exclusivo também impede que senhas iguais produzam necessariamente o mesmo hash e dificulta o uso de tabelas pré-calculadas.

BANCO DE DADOS
- Banco local SQLite: usuarios.db (criado automaticamente ao executar app.py).
- Tabela usuarios: id, usuario, senha_hash e criado_em.
- Consultas SQL usam parâmetros, e o nome de usuário possui restrição de unicidade sem diferenciar maiúsculas/minúsculas.
- usuarios.db é dado gerado localmente e não deve ser enviado ao Git.

COMO PREPARAR O AMBIENTE (WINDOWS / POWERSHELL)
Na raiz da pasta do projeto:
  py -m venv .venv
  .\.venv\Scripts\Activate.ps1
  py -m pip install -r requirements.txt

COMO EXECUTAR
Testes automatizados:
  py -m pytest -v

Demonstração integrada das Entregas 1 e 2:
  py demo.py

Aplicação de cadastro e login:
  py app.py

Demonstração manual de adulteração da Entrega 1:
  py testes_erros.py gerar
  py testes_erros.py abrir
  py testes_erros.py abrir --outro-destino

Na demonstração de criptografia, a senha protege os arquivos PEM. É possível definir ENTREGA1_SENHA na sessão do PowerShell para evitar a pergunta interativa. Não coloque senhas reais em arquivos ou no Git.

TESTES
- test_cripto.py: testes positivos e negativos da criptografia híbrida e assinatura digital da Entrega 1.
- test_auth.py: testes de cadastro, login correto/incorreto, hash Argon2id, salt aleatório, usuário duplicado, validação e hash adulterado da Entrega 2.
- testes_erros.py: ferramenta de demonstração manual; não é coletada automaticamente pelo pytest por seu nome.

SEGURANÇA E LIMITES
- Não armazena senhas em texto puro. O hash não é criptografia e não pode ser revertido para recuperar a senha original.
- A comparação é realizada por PasswordHasher.verify() da biblioteca argon2-cffi; não há comparação manual de hashes.
- A aplicação é didática e local. Não implementa limitação de tentativas, recuperação de senha, MFA, sessão web, proteção contra enumeração por tempo ou controle de acesso multiusuário.
- A mensagem de erro de login é genérica, mas isso não substitui controles de taxa de tentativas e mitigação de diferenças de tempo.
- Sem certificados/PKI: as chaves públicas da Entrega 1 são trocadas diretamente.
- Sem proteção contra reenvio de um pacote legítimo (replay).
- Chaves privadas da Entrega 1 ficam em arquivos locais protegidos por senha; em produção, usar cofre de segredos e política de rotação.
- O SQLite é adequado ao laboratório local, não substitui um banco configurado e administrado para produção.
- Usar somente dados fictícios e ambiente próprio/autorizado.

DEPENDÊNCIAS
- cryptography: criptografia híbrida e assinaturas digitais.
- argon2-cffi: hash e verificação de senhas com Argon2id.
- pytest: testes automatizados.

REFERÊNCIAS TÉCNICAS
- OWASP Application Security Verification Standard (ASVS) 5.0.0, requisitos de armazenamento de senhas e autenticação.
- OWASP Password Storage Cheat Sheet.
- Documentação oficial argon2-cffi.
- Documentação oficial Python sqlite3.
