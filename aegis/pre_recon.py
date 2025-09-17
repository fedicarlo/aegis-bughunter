"""
AEGIS Bug Hunter - Pre Reconnaissance
Módulo responsável pelo reconhecimento inicial do alvo
"""

import os
import json
import time
import socket
import requests
from urllib.parse import urlparse
from datetime import datetime

def criar_diretorio_output(target_url):
    """Cria diretório de output para o alvo"""
    site_name = target_url.replace('https://', '').replace('http://', '').replace('/', '_')
    output_dir = f"output/{site_name}"
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def coletar_headers(target_url, timeout=10):
    """Coleta headers HTTP do alvo"""
    headers_info = {
        "url": target_url,
        "timestamp": datetime.now().isoformat(),
        "headers": {},
        "status_code": None,
        "response_time": None,
        "erro": None
    }
    
    try:
        print(f"[pre_recon] 📡 Coletando headers de {target_url}")
        
        inicio = time.time()
        response = requests.get(target_url, timeout=timeout, allow_redirects=True)
        fim = time.time()
        
        headers_info["headers"] = dict(response.headers)
        headers_info["status_code"] = response.status_code
        headers_info["response_time"] = round((fim - inicio) * 1000, 2)  # em ms
        headers_info["url_final"] = response.url
        headers_info["redirects"] = len(response.history)
        
        print(f"[pre_recon] ✅ Status: {response.status_code} | Tempo: {headers_info['response_time']}ms")
        
    except requests.exceptions.Timeout:
        headers_info["erro"] = "Timeout na requisição"
        print(f"[pre_recon] ⏰ Timeout ao acessar {target_url}")
    except requests.exceptions.ConnectionError:
        headers_info["erro"] = "Erro de conexão"
        print(f"[pre_recon] 🔌 Erro de conexão com {target_url}")
    except Exception as e:
        headers_info["erro"] = str(e)
        print(f"[pre_recon] ❌ Erro inesperado: {str(e)}")
    
    return headers_info

def analisar_tecnologias(headers):
    """Analisa tecnologias baseado nos headers"""
    tecnologias = {
        "servidor": None,
        "linguagem": None,
        "framework": None,
        "cdn": None,
        "waf": None,
        "cms": None
    }
    
    # Análise do servidor
    if "server" in headers:
        servidor = headers["server"].lower()
        if "nginx" in servidor:
            tecnologias["servidor"] = "Nginx"
        elif "apache" in servidor:
            tecnologias["servidor"] = "Apache"
        elif "iis" in servidor:
            tecnologias["servidor"] = "IIS"
        elif "cloudflare" in servidor:
            tecnologias["cdn"] = "Cloudflare"
    
    # Análise de linguagem/framework
    if "x-powered-by" in headers:
        powered_by = headers["x-powered-by"].lower()
        if "php" in powered_by:
            tecnologias["linguagem"] = "PHP"
        elif "asp.net" in powered_by:
            tecnologias["linguagem"] = "ASP.NET"
        elif "express" in powered_by:
            tecnologias["framework"] = "Express.js"
    
    # Análise de CDN
    if "cf-ray" in headers:
        tecnologias["cdn"] = "Cloudflare"
    elif "x-amz-cf-id" in headers:
        tecnologias["cdn"] = "Amazon CloudFront"
    
    # Análise de WAF
    waf_headers = [
        "x-sucuri-id", "x-sucuri-cache",
        "cf-ray", "cf-cache-status",
        "x-mod-pagespeed", "x-page-speed"
    ]
    
    for header in waf_headers:
        if header in headers:
            if "sucuri" in header:
                tecnologias["waf"] = "Sucuri"
            elif "cf-" in header:
                tecnologias["waf"] = "Cloudflare"
            break
    
    return tecnologias

def verificar_portas_comuns(hostname):
    """Verifica portas comuns abertas"""
    portas_comuns = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
    portas_abertas = []
    
    print(f"[pre_recon] 🔍 Verificando portas comuns em {hostname}")
    
    for porta in portas_comuns:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            resultado = sock.connect_ex((hostname, porta))
            sock.close()
            
            if resultado == 0:
                portas_abertas.append(porta)
                print(f"[pre_recon] 🟢 Porta {porta} aberta")
        except:
            continue
    
    return portas_abertas

def coletar_certificado_ssl(hostname, porta=443):
    """Coleta informações do certificado SSL"""
    import ssl
    
    cert_info = {
        "tem_ssl": False,
        "emissor": None,
        "valido_ate": None,
        "algoritmo": None,
        "erro": None
    }
    
    try:
        print(f"[pre_recon] 🔒 Verificando certificado SSL")
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, porta), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                cert_info["tem_ssl"] = True
                cert_info["emissor"] = cert.get("issuer", [{}])[0].get("organizationName", "Desconhecido")
                cert_info["valido_ate"] = cert.get("notAfter")
                cert_info["algoritmo"] = cert.get("signatureAlgorithm", "Desconhecido")
                
                print(f"[pre_recon] ✅ SSL válido | Emissor: {cert_info['emissor']}")
                
    except Exception as e:
        cert_info["erro"] = str(e)
        print(f"[pre_recon] ⚠️ Erro ao verificar SSL: {str(e)}")
    
    return cert_info

def executar(target_url):
    """Executa o reconhecimento inicial completo"""
    print(f"[pre_recon] 🧠 Iniciando reconhecimento de {target_url}")
    
    # Cria diretório de output
    output_dir = criar_diretorio_output(target_url)
    
    # Extrai hostname
    parsed_url = urlparse(target_url)
    hostname = parsed_url.netloc
    
    # Coleta headers
    headers_info = coletar_headers(target_url)
    
    # Analisa tecnologias
    tecnologias = {}
    if headers_info["headers"]:
        tecnologias = analisar_tecnologias(headers_info["headers"])
    
    # Verifica portas
    portas_abertas = verificar_portas_comuns(hostname)
    
    # Verifica SSL
    cert_info = {}
    if parsed_url.scheme == "https":
        cert_info = coletar_certificado_ssl(hostname)
    
    # Compila resultado final
    resultado_final = {
        "target_url": target_url,
        "hostname": hostname,
        "timestamp": datetime.now().isoformat(),
        "headers": headers_info,
        "tecnologias": tecnologias,
        "portas_abertas": portas_abertas,
        "certificado_ssl": cert_info,
        "resumo": {
            "status_http": headers_info.get("status_code"),
            "servidor": tecnologias.get("servidor", "Desconhecido"),
            "tem_waf": tecnologias.get("waf") is not None,
            "tem_ssl": cert_info.get("tem_ssl", False),
            "portas_encontradas": len(portas_abertas)
        }
    }
    
    # Salva resultado
    arquivo_saida = f"{output_dir}/pre_recon.json"
    with open(arquivo_saida, "w", encoding="utf-8") as f:
        json.dump(resultado_final, f, indent=4, ensure_ascii=False)
    
    print(f"[pre_recon] ✅ Reconhecimento finalizado")
    print(f"[pre_recon] 📊 Servidor: {tecnologias.get('servidor', 'Desconhecido')}")
    print(f"[pre_recon] 🛡️ WAF detectado: {'Sim' if tecnologias.get('waf') else 'Não'}")
    print(f"[pre_recon] 🔒 SSL: {'Sim' if cert_info.get('tem_ssl') else 'Não'}")
    print(f"[pre_recon] 🚪 Portas abertas: {len(portas_abertas)}")
    print(f"[pre_recon] 💾 Resultado salvo em: {arquivo_saida}")
    
    return resultado_final

