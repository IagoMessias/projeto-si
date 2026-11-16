ENTREGA 1 - Criptografia assimétrica e confiança
Projeto Integrador - Segurança da Informação - Unit

O QUE FAZ
Protege uma mensagem enviada a outro serviço e permite ao destino verificar quem a enviou. Usa cifragem híbrida (sigilo) e assinatura digital (autenticidade), com a biblioteca cryptography. Nenhum algoritmo próprio.

COMO FUNCIONA
1. O remetente cifra a mensagem com AES-256-GCM e cifra a chave AES com RSA-OAEP (chave pública do destino).
2. O remetente assina o pacote com Ed25519.
3. O destino verifica a assinatura e só depois decifra.

ALGORITMOS E PARÂMETROS
- RSA-OAEP: 3072 bits, e = 65537, SHA-256
- AES-256-GCM: nonce de 96 bits aleatório por mensagem, tag de 128 bits
- Ed25519: assinatura digital
- Chaves em disco: PEM PKCS#8 protegido por senha

CHAVES
- Dois pares: RSA (destino) e Ed25519 (remetente).
- As chaves privadas ficam em chaves/*.pem, protegidas por senha. Os .pem não vão para o Git (.gitignore).
- A chave AES é nova a cada mensagem.
- Em produção: cofre de segredos e rotação periódica.

COMO RODAR (Windows, PowerShell)
  py -m venv ..\.venv
..\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -v
py demo.py

TESTES
21 testes automáticos (pytest): ida e volta, e rejeição de adulteração, assinatura de atacante, destinatário errado e pacote malformado. As saídas ficam na pasta evidencias.

LIMITES
- Sem certificados/PKI: as chaves públicas são trocadas diretamente.
- Sem proteção contra reenvio de pacote (replay).
- Sem sigilo futuro: vazar a chave RSA expõe mensagens antigas.
- Chaves em arquivo, não em cofre.
- Não protege o transporte (usar também TLS).

Mais detalhes: ver o documento técnico.
