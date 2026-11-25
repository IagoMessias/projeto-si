| Porta | Protocolo | Serviço | Necessidade | Risco | Recomendação |
|---|---|---|---|---|---|
| 22 | tcp | SSH OpenSSH for_Windows_9.5 | Necessária | Médio | Manter, com endurecimento: Desativar PasswordAuthentication, manter PubkeyAuthentication, limitar ListenAddress a 127.0.0.1 e restringir AllowUsers. |
| 8000 | tcp | HTTP local SimpleHTTPServer 0.6 | Necessária | Médio | Manter, com endurecimento: Manter somente durante o laboratório e vinculado a 127.0.0.1. |
| 8001 | tcp | HTTP extra SimpleHTTPServer 0.6 | Não necessária | Médio | Fechar: desativar o serviço e bloquear a porta no firewall. |
