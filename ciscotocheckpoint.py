#!/usr/bin/env python3
import re

def parse_vpn_file(filename):
    """
    Lê o arquivo Cisco e extrai os principais parâmetros necessários.
    """
    data = {}
    with open(filename, "r", encoding="utf-8") as f:
        text = f.read()
    
    # Pre-shared key (chave compartilhada)
    m = re.search(r'pre-shared-key\s+(\S+)', text)
    if m:
        data["pre_shared_key"] = m.group(1)
    else:
        data["pre_shared_key"] = "12345"
    
    # IKE: criptografia, integridade e Diffie-Hellman
    m = re.search(r'crypto ikev2 proposal.*\nencryption\s+(\S+)', text, re.MULTILINE)
    if m:
        data["ike_encryption"] = m.group(1)
    else:
        data["ike_encryption"] = "aes-cbc-256"
    
    m = re.search(r'integrity\s+(\S+)', text)
    if m:
        data["ike_integrity"] = m.group(1)
    else:
        data["ike_integrity"] = "sha1"
    
    m = re.search(r'group\s+(\d+)', text)
    if m:
        data["ike_dh_group"] = m.group(1)
    else:
        data["ike_dh_group"] = "2"
    
    # Lifetime (utilizado para IKE e IPsec)
    m = re.search(r'lifetime\s+(\d+)', text)
    if m:
        data["lifetime"] = m.group(1)
    else:
        data["lifetime"] = "3600"
    
    # IPsec: Transform Set (procura por "esp-gcm")
    m = re.search(r'esp-gcm\s+(\d+)', text)
    if m:
        data["ipsec_transform_set"] = f"esp-gcm-{m.group(1)}"
    else:
        data["ipsec_transform_set"] = "esp-gcm-256"
    
    # Gateway: IP on-premises (local VPN IP)
    m = re.search(r'On-premises VPN IP:\s*(\S+)', text)
    if m:
        data["local_vpn_ip"] = m.group(1)
    else:
        data["local_vpn_ip"] = "38.104.95.242"
    
    # Gateways remotos: public IPs
    public_ips = re.findall(r'Public IP \d+:\s*(\S+)', text)
    if public_ips:
        data["remote_gateways"] = public_ips
    else:
        data["remote_gateways"] = ["20.119.73.47", "20.84.65.117"]
    
    # Domínios de criptografia
    # Local (on-premises): CIDR da rede on-premises
    m = re.search(r'On-premises address prefixes:.*CIDR:\s*(\S+)', text, re.DOTALL)
    if m:
        data["local_network"] = m.group(1)
    else:
        data["local_network"] = "192.168.101.0/24"
    
    # Remoto (Virtual network): CIDR da rede virtual do Azure
    m = re.search(r'Virtual network address space:.*CIDR:\s*(\S+)', text, re.DOTALL)
    if m:
        data["remote_network"] = m.group(1)
    else:
        data["remote_network"] = "10.0.0.0/16"
    
    return data

def generate_checkpoint_config(data):
    """
    Gera a configuração para CheckPoint R81.20 usando os comandos mgmt_cli.
    """
    lines = []
    lines.append("# CheckPoint VPN Configuration - Comunidade: ParaCheckPoint")
    lines.append("")
    
    # 1. Configuração do Gateway VPN - IKE (Fase 1)
    lines.append("# 1. Configuração do Gateway VPN com parâmetros IKE (Fase 1 - IKEv2)")
    lines.append('mgmt_cli set-vpn-ike-gateway name "CheckPoint" \\')
    lines.append('    ike-version "ikev2" \\')
    # Converter o algoritmo, se necessário (ex.: "aes-cbc-256" para "aes256")
    ike_encryption = data.get("ike_encryption", "aes-cbc-256")
    if "aes-cbc-256" in ike_encryption:
        ike_encryption = "aes256"
    lines.append(f'    encryption "{ike_encryption}" \\')
    lines.append(f'    hash-algorithm "{data.get("ike_integrity", "sha1")}" \\')
    lines.append(f'    dh-group "group{data.get("ike_dh_group", "2")}" \\')
    lines.append(f'    lifetime "{data.get("lifetime", "3600")}" \\')
    lines.append(f'    pre-shared-key "{data.get("pre_shared_key", "12345")}" \\')
    lines.append('    --format json')
    lines.append('echo "Gateway IKE atualizado para IKEv2 com os parâmetros definidos."')
    lines.append("")
    
    # 2. Configuração do Gateway VPN - IPsec (Fase 2)
    lines.append("# 2. Configuração do Gateway VPN com parâmetros IPsec (Fase 2)")
    lines.append('mgmt_cli set-vpn-ipsec-gateway name "CheckPoint" \\')
    lines.append(f'    transform-set "{data.get("ipsec_transform_set", "esp-gcm-256")}" \\')
    lines.append(f'    lifetime "{data.get("lifetime", "3600")}" \\')
    lines.append('    --format json')
    lines.append('echo "Gateway IPsec atualizado com o transform-set definido."')
    lines.append("")
    
    # 3. Criação da Comunidade VPN
    remote_gateways = data.get("remote_gateways", ["20.119.73.47", "20.84.65.117"])
    remote_gateways_str = ",".join(remote_gateways)
    lines.append("# 3. Criação da Comunidade VPN")
    lines.append('mgmt_cli add-vpn-community name "ParaCheckPoint" \\')
    lines.append('    local-gateway "CheckPoint" \\')
    lines.append(f'    remote-gateways "{remote_gateways_str}" \\')
    lines.append('    encryption-method "ikev2" \\')
    lines.append('    authentication "pre-shared-key" \\')
    lines.append(f'    pre-shared-key "{data.get("pre_shared_key", "12345")}" \\')
    lines.append('    --format json')
    lines.append('echo "Comunidade VPN \'ParaCheckPoint\' criada."')
    lines.append("")
    
    # 4. Definição dos Domínios de Criptografia (Encryption Domains)
    lines.append("# 4. Definição dos Domínios de Criptografia (Encryption Domains)")
    local_network = data.get("local_network", "192.168.101.0/24")
    remote_network = data.get("remote_network", "10.0.0.0/16")
    lines.append('mgmt_cli set-vpn-community name "ParaCheckPoint" \\')
    lines.append(f'    local-network "{local_network}" \\')
    lines.append('    --format json')
    lines.append(f'echo "Domínio local definido como {local_network}."')
    lines.append("")
    lines.append('mgmt_cli set-vpn-community name "ParaCheckPoint" \\')
    lines.append(f'    remote-network "{remote_network}" \\')
    lines.append('    --format json')
    lines.append(f'echo "Domínio remoto definido como {remote_network}."')
    lines.append("")
    
    # 5. (Opcional) Configuração de Rota Estática
    lines.append("# 5. (Opcional) Configuração de Rota Estática para o tráfego VPN")
    lines.append('mgmt_cli add-route name "VPN Route" \\')
    lines.append(f'    destination "{remote_network}" \\')
    lines.append('    nexthop "VPN_Tunnel_Interface" \\')
    lines.append('    --format json')
    lines.append(f'echo "Rota para {remote_network} adicionada."')
    lines.append("")
    lines.append('echo "Configuração VPN para CheckPoint R81.20 concluída."')
    
    return "\n".join(lines)

if __name__ == "__main__":
    input_filename = "vpnazure.txt"
    output_filename = "checkpoint_vpn_config.sh"
    
    parsed_data = parse_vpn_file(input_filename)
    cp_config = generate_checkpoint_config(parsed_data)
    
    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(cp_config)
    
    print(f"Arquivo de configuração gerado: {output_filename}")
