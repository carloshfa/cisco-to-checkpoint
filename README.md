# cisco-to-checkpoint
Código python to convert cisco generic configuration para Checkpoint 81.20 format

Como utilizar o script
Certifique-se de que o arquivo "vpnazure.txt" esteja na mesma pasta que o script.

Dê permissão de execução (em sistemas Unix/Linux):

chmod +x ciscotocheckpoint.py

Execute o script:
./ciscotocheckpoint.py.py
Isso gerará um arquivo chamado checkpoint_vpn_config.sh com os comandos de configuração para CheckPoint R81.20.

Considerações
Ajustes Futuros:
Se o arquivo Cisco tiver variações ou informações adicionais, você poderá aprimorar as expressões regulares e a lógica do script para extrair os dados corretamente.

Validação Manual:
Após a geração, revise o arquivo checkpoint_vpn_config.sh e ajuste os comandos conforme necessário para refletir com precisão a configuração desejada no ambiente CheckPoint.

Execução dos comandos:
O arquivo gerado utiliza comandos mgmt_cli, portanto, certifique-se de que o ambiente de gerenciamento esteja devidamente configurado e autenticado para aplicar as configurações.

Este script serve como um exemplo inicial e pode ser expandido conforme suas necessidades. Se precisar de mais detalhes ou adaptações, estou à disposição para ajudar!
