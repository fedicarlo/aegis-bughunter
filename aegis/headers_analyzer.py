"""
AEGIS Bug Hunter - Headers Analyzer
Módulo responsável pela análise detalhada de headers HTTP
"""

import os
import json
import requests
from datetime import datetime

def analisar_headers_seguranca(headers):
    """Analisa headers de segurança"""
    headers_seguranca = {
        "content-security-policy": {
            "presente": False,
            "valor": None,
            "nivel_seguranca": "baixo"
        },
        "strict-transport-security": {
            "presente": False,
            "valor": None,
            "max_age": None
        },
        "x-frame-options": {
            "presente": False,
            "valor": None,
            "protege_clickjacking": False
        },
        "x-content-type-options": {
            "presente": False,
            "valor": None,
            "protege_mime_sniffing": False
        },
        "x-xss-protection": {
            "presente": False,
            "valor": None,
            "ativo": False
        },
        "referrer-policy": {
            "presente": False,
            "valor": None
        }
    }
    
    # Analisa Content Security Policy
    if "content-security-policy" in headers:
        csp = headers["content-security-policy"]
        headers_seguranca["content-security-policy"]["presente"] = True
        headers_seguranca["content-security-policy"]["valor"] = csp
        
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            headers_seguranca["content-security-policy"]["nivel_seguranca"] = "medio"
        else:
            headers_seguranca["content-security-policy"]["nivel_seguranca"] = "alto"
    
    # Analisa HSTS
    if "strict-transport-security" in headers:
        hsts = headers["strict-transport-security"]
        headers_seguranca["strict-transport-security"]["presente"] = True
        headers_seguranca["strict-transport-security"]["valor"] = hsts
        
        if "max-age=" in hsts:
            try:
                max_age = hsts.split("max-age=")[1].split(";")[0]
                headers_seguranca["strict-transport-security"]["max_age"] = int(max_age)
            except:
                pass
    
    # Analisa X-Frame-Options
    if "x-frame-options" in headers:
        xfo = headers["x-frame-options"].upper()
        headers_seguranca["x-frame-options"]["presente"] = True
        headers_seguranca["x-frame-options"]["valor"] = xfo
        headers_seguranca["x-frame-options"]["protege_clickjacking"] = xfo in ["DENY", "SAMEORIGIN"]
    
    # Analisa X-Content-Type-Options
    if "x-content-type-options" in headers:
        xcto = headers["x-content-type-options"].lower()
        headers_seguranca["x-content-type-options"]["presente"] = True
        headers_seguranca["x-content-type-options"]["valor"] = xcto
        headers_seguranca["x-content-type-options"]["protege_mime_sniffing"] = xcto == "nosniff"
    
    # Analisa X-XSS-Protection
    if "x-xss-protection" in headers:
        xxp = headers["x-xss-protection"]
        headers_seguranca["x-xss-protection"]["presente"] = True
        headers_seguranca["x-xss-protection"]["valor"] = xxp
        headers_seguranca["x-xss-protection"]["ativo"] = xxp.startswith("1")
    
    # Analisa Referrer Policy
    if "referrer-policy" in headers:
        rp = headers["referrer-policy"]
        headers_seguranca["referrer-policy"]["presente"] = True
        headers_seguranca["referrer-policy"]["valor"] = rp
    
    return headers_seguranca

def detectar_waf_avancado(headers, response_text=""):
    """Detecta WAF baseado em headers e conteúdo"""
    wafs_detectados = []
    
    # Detecção por headers
    waf_signatures = {
        "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid"],
        "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
        "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
        "Incapsula": ["x-iinfo", "incap_ses"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "F5 BIG-IP": ["bigipserver", "f5-bigip"],
        "Barracuda": ["barra", "barracuda"],
        "Fortinet": ["fortigate", "fortiweb"],
        "Akamai": ["akamai", "x-akamai"],
        "Fastly": ["fastly", "x-served-by"]
    }
    
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    
    for waf_name, signatures in waf_signatures.items():
        for signature in signatures:
            for header_name, header_value in headers_lower.items():
                if signature in header_name or signature in header_value:
                    if waf_name not in wafs_detectados:
                        wafs_detectados.append(waf_name)
    
    # Detecção por conteúdo da resposta
    if response_text:
        response_lower = response_text.lower()
        content_signatures = {
            "Cloudflare": ["cloudflare", "cf-error"],
            "Sucuri": ["sucuri", "access denied"],
            "Incapsula": ["incapsula", "request unsuccessful"],
            "ModSecurity": ["mod_security", "not acceptable"]
        }
        
        for waf_name, signatures in content_signatures.items():
            for signature in signatures:
                if signature in response_lower and waf_name not in wafs_detectados:
                    wafs_detectados.append(waf_name)
    
    return wafs_detectados

def analisar_cookies(headers):
    """Analisa cookies de segurança"""
    cookies_info = {
        "cookies_encontrados": [],
        "problemas_seguranca": []
    }
    
    if "set-cookie" in headers:
        cookies = headers["set-cookie"]
        if isinstance(cookies, str):
            cookies = [cookies]
        elif isinstance(cookies, list):
            pass
        else:
            cookies = [str(cookies)]
        
        for cookie in cookies:
            cookie_info = {
                "valor": cookie,
                "secure": "secure" in cookie.lower(),
                "httponly": "httponly" in cookie.lower(),
                "samesite": None
            }
            
            # Verifica SameSite
            if "samesite=" in cookie.lower():
                samesite_part = cookie.lower().split("samesite=")[1].split(";")[0]
                cookie_info["samesite"] = samesite_part.strip()
            
            cookies_info["cookies_encontrados"].append(cookie_info)
            
            # Identifica problemas de segurança
            if not cookie_info["secure"]:
                cookies_info["problemas_seguranca"].append("Cookie sem flag Secure")
            if not cookie_info["httponly"]:
                cookies_info["problemas_seguranca"].append("Cookie sem flag HttpOnly")
            if not cookie_info["samesite"]:
                cookies_info["problemas_seguranca"].append("Cookie sem SameSite")
    
    return cookies_info

def testar_metodos_http(target_url):
    """Testa métodos HTTP permitidos"""
    metodos = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]
    metodos_permitidos = []
    
    print(f"[headers_analyzer] 🔍 Testando métodos HTTP")
    
    for metodo in metodos:
        try:
            response = requests.request(metodo, target_url, timeout=5)
            if response.status_code not in [405, 501]:  # Method Not Allowed, Not Implemented
                metodos_permitidos.append({
                    "metodo": metodo,
                    "status_code": response.status_code,
                    "permitido": True
                })
            else:
                metodos_permitidos.append({
                    "metodo": metodo,
                    "status_code": response.status_code,
                    "permitido": False
                })
        except:
            metodos_permitidos.append({
                "metodo": metodo,
                "status_code": None,
                "permitido": False
            })
    
    return metodos_permitidos

def calcular_score_seguranca(headers_seguranca):
    """Calcula score de segurança baseado nos headers"""
    score = 0
    max_score = 6
    
    if headers_seguranca["content-security-policy"]["presente"]:
        score += 1
    if headers_seguranca["strict-transport-security"]["presente"]:
        score += 1
    if headers_seguranca["x-frame-options"]["protege_clickjacking"]:
        score += 1
    if headers_seguranca["x-content-type-options"]["protege_mime_sniffing"]:
        score += 1
    if headers_seguranca["x-xss-protection"]["ativo"]:
        score += 1
    if headers_seguranca["referrer-policy"]["presente"]:
        score += 1
    
    percentual = (score / max_score) * 100
    
    if percentual >= 80:
        nivel = "Alto"
    elif percentual >= 50:
        nivel = "Médio"
    else:
        nivel = "Baixo"
    
    return {
        "score": score,
        "max_score": max_score,
        "percentual": round(percentual, 1),
        "nivel": nivel
    }

def executar(target_url):
    """Executa análise completa de headers"""
    print(f"[headers_analyzer] 🔍 Analisando headers de {target_url}")
    
    try:
        # Faz requisição para obter headers
        response = requests.get(target_url, timeout=10)
        headers = dict(response.headers)
        response_text = response.text
        
        # Análises
        headers_seguranca = analisar_headers_seguranca(headers)
        wafs_detectados = detectar_waf_avancado(headers, response_text)
        cookies_info = analisar_cookies(headers)
        metodos_http = testar_metodos_http(target_url)
        score_seguranca = calcular_score_seguranca(headers_seguranca)
        
        # Compila resultado
        resultado = {
            "target_url": target_url,
            "timestamp": datetime.now().isoformat(),
            "headers_raw": headers,
            "headers_seguranca": headers_seguranca,
            "wafs_detectados": wafs_detectados,
            "cookies": cookies_info,
            "metodos_http": metodos_http,
            "score_seguranca": score_seguranca,
            "resumo": {
                "total_headers": len(headers),
                "tem_waf": len(wafs_detectados) > 0,
                "nivel_seguranca": score_seguranca["nivel"],
                "metodos_perigosos": [m["metodo"] for m in metodos_http if m["permitido"] and m["metodo"] in ["PUT", "DELETE", "TRACE"]]
            }
        }
        
        # Salva resultado
        site_name = target_url.replace('https://', '').replace('http://', '').replace('/', '_')
        output_dir = f"output/{site_name}"
        os.makedirs(output_dir, exist_ok=True)
        
        arquivo_saida = f"{output_dir}/headers_analysis.json"
        with open(arquivo_saida, "w", encoding="utf-8") as f:
            json.dump(resultado, f, indent=4, ensure_ascii=False)
        
        print(f"[headers_analyzer] ✅ Análise concluída")
        print(f"[headers_analyzer] 🛡️ WAFs detectados: {', '.join(wafs_detectados) if wafs_detectados else 'Nenhum'}")
        print(f"[headers_analyzer] 🔒 Score de segurança: {score_seguranca['percentual']}% ({score_seguranca['nivel']})")
        print(f"[headers_analyzer] 💾 Resultado salvo em: {arquivo_saida}")
        
        return resultado
        
    except Exception as e:
        print(f"[headers_analyzer] ❌ Erro na análise: {str(e)}")
        return {"erro": str(e)}

