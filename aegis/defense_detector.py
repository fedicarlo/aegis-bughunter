"""
AEGIS Bug Hunter - Defense Detector
Módulo responsável por detectar e analisar defesas do alvo
"""

import os
import json
import time
import requests
import random
from datetime import datetime
from urllib.parse import urlparse

class DefenseDetector:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.defesas_detectadas = []
        
    def _testar_waf_cloudflare(self):
        """Testa especificamente para Cloudflare"""
        indicadores = {
            "headers": ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"],
            "content": ["cloudflare", "cf-error", "attention required"],
            "status_codes": [403, 503]
        }
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Verifica headers
            for header in indicadores["headers"]:
                if header in response.headers:
                    return {
                        "detectado": True,
                        "tipo": "Cloudflare",
                        "evidencia": f"Header encontrado: {header}",
                        "confianca": 0.95
                    }
            
            # Verifica conteúdo
            content_lower = response.text.lower()
            for indicador in indicadores["content"]:
                if indicador in content_lower:
                    return {
                        "detectado": True,
                        "tipo": "Cloudflare",
                        "evidencia": f"Conteúdo encontrado: {indicador}",
                        "confianca": 0.9
                    }
            
            # Testa com payload suspeito
            payload_test = self.target_url + "?test=<script>alert('xss')</script>"
            response_test = self.session.get(payload_test, timeout=10)
            
            if response_test.status_code in indicadores["status_codes"]:
                if any(ind in response_test.text.lower() for ind in indicadores["content"]):
                    return {
                        "detectado": True,
                        "tipo": "Cloudflare",
                        "evidencia": f"Bloqueio detectado com payload: {response_test.status_code}",
                        "confianca": 0.85
                    }
        
        except Exception:
            pass
        
        return {"detectado": False}
    
    def _testar_waf_aws(self):
        """Testa para AWS WAF"""
        indicadores = {
            "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amzn-trace-id"],
            "content": ["aws", "amazon", "request blocked"],
            "status_codes": [403, 503]
        }
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Verifica headers
            for header in indicadores["headers"]:
                if header in response.headers:
                    return {
                        "detectado": True,
                        "tipo": "AWS WAF",
                        "evidencia": f"Header encontrado: {header}",
                        "confianca": 0.9
                    }
            
            # Testa com payload SQL injection
            payload_test = self.target_url + "?id=1' OR '1'='1"
            response_test = self.session.get(payload_test, timeout=10)
            
            if response_test.status_code == 403:
                content_lower = response_test.text.lower()
                if any(ind in content_lower for ind in indicadores["content"]):
                    return {
                        "detectado": True,
                        "tipo": "AWS WAF",
                        "evidencia": "Bloqueio de SQL injection detectado",
                        "confianca": 0.8
                    }
        
        except Exception:
            pass
        
        return {"detectado": False}
    
    def _testar_waf_sucuri(self):
        """Testa para Sucuri WAF"""
        indicadores = {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "content": ["sucuri", "access denied", "website firewall"],
            "status_codes": [403, 406]
        }
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Verifica headers
            for header in indicadores["headers"]:
                if header in response.headers:
                    return {
                        "detectado": True,
                        "tipo": "Sucuri",
                        "evidencia": f"Header encontrado: {header}",
                        "confianca": 0.95
                    }
            
            # Testa com payload XSS
            payload_test = self.target_url + "?search=<img src=x onerror=alert(1)>"
            response_test = self.session.get(payload_test, timeout=10)
            
            if response_test.status_code in indicadores["status_codes"]:
                content_lower = response_test.text.lower()
                if any(ind in content_lower for ind in indicadores["content"]):
                    return {
                        "detectado": True,
                        "tipo": "Sucuri",
                        "evidencia": "Bloqueio de XSS detectado",
                        "confianca": 0.85
                    }
        
        except Exception:
            pass
        
        return {"detectado": False}
    
    def _testar_waf_incapsula(self):
        """Testa para Incapsula/Imperva"""
        indicadores = {
            "headers": ["x-iinfo", "incap_ses"],
            "content": ["incapsula", "imperva", "request unsuccessful"],
            "status_codes": [403, 503]
        }
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Verifica headers
            for header in indicadores["headers"]:
                if header in response.headers:
                    return {
                        "detectado": True,
                        "tipo": "Incapsula/Imperva",
                        "evidencia": f"Header encontrado: {header}",
                        "confianca": 0.95
                    }
            
            # Testa com payload command injection
            payload_test = self.target_url + "?cmd=; cat /etc/passwd"
            response_test = self.session.get(payload_test, timeout=10)
            
            if response_test.status_code in indicadores["status_codes"]:
                content_lower = response_test.text.lower()
                if any(ind in content_lower for ind in indicadores["content"]):
                    return {
                        "detectado": True,
                        "tipo": "Incapsula/Imperva",
                        "evidencia": "Bloqueio de command injection detectado",
                        "confianca": 0.8
                    }
        
        except Exception:
            pass
        
        return {"detectado": False}
    
    def _testar_rate_limiting(self):
        """Testa para rate limiting"""
        print(f"[defense_detector] 🔄 Testando rate limiting...")
        
        try:
            # Faz múltiplas requisições rápidas
            tempos_resposta = []
            status_codes = []
            
            for i in range(10):
                inicio = time.time()
                response = self.session.get(self.target_url, timeout=5)
                fim = time.time()
                
                tempos_resposta.append(fim - inicio)
                status_codes.append(response.status_code)
                
                # Verifica se foi bloqueado
                if response.status_code == 429:
                    return {
                        "detectado": True,
                        "tipo": "Rate Limiting",
                        "evidencia": f"HTTP 429 na requisição {i+1}",
                        "confianca": 0.95,
                        "detalhes": {
                            "requisicoes_ate_bloqueio": i+1,
                            "retry_after": response.headers.get("Retry-After", "N/A")
                        }
                    }
                
                # Verifica se tempo de resposta aumentou drasticamente
                if i > 3 and tempos_resposta[-1] > (sum(tempos_resposta[:-1]) / len(tempos_resposta[:-1])) * 3:
                    return {
                        "detectado": True,
                        "tipo": "Rate Limiting (Soft)",
                        "evidencia": f"Tempo de resposta aumentou drasticamente: {tempos_resposta[-1]:.2f}s",
                        "confianca": 0.7,
                        "detalhes": {
                            "tempo_medio_inicial": sum(tempos_resposta[:-1]) / len(tempos_resposta[:-1]),
                            "tempo_atual": tempos_resposta[-1]
                        }
                    }
                
                time.sleep(0.1)  # Pequeno delay entre requisições
        
        except Exception:
            pass
        
        return {"detectado": False}
    
    def _testar_captcha(self):
        """Testa para presença de CAPTCHA"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            content_lower = response.text.lower()
            
            captcha_indicators = [
                "recaptcha", "captcha", "hcaptcha", "turnstile",
                "prove you are human", "verify you are human",
                "i'm not a robot", "security check"
            ]
            
            for indicator in captcha_indicators:
                if indicator in content_lower:
                    return {
                        "detectado": True,
                        "tipo": "CAPTCHA",
                        "evidencia": f"Indicador encontrado: {indicator}",
                        "confianca": 0.8
                    }
            
            # Verifica por scripts de CAPTCHA
            captcha_scripts = [
                "recaptcha/api.js", "hcaptcha.com", "challenges.cloudflare.com"
            ]
            
            for script in captcha_scripts:
                if script in response.text:
                    return {
                        "detectado": True,
                        "tipo": "CAPTCHA",
                        "evidencia": f"Script de CAPTCHA encontrado: {script}",
                        "confianca": 0.9
                    }
        
        except Exception:
            pass
        
        return {"detectado": False}
    
    def _testar_csrf_protection(self):
        """Testa para proteção CSRF"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            # Verifica por tokens CSRF
            csrf_indicators = [
                'name="csrf_token"', 'name="_token"', 'name="authenticity_token"',
                'csrf-token', '_csrf', 'csrfmiddlewaretoken'
            ]
            
            for indicator in csrf_indicators:
                if indicator in response.text:
                    return {
                        "detectado": True,
                        "tipo": "CSRF Protection",
                        "evidencia": f"Token CSRF encontrado: {indicator}",
                        "confianca": 0.85
                    }
            
            # Verifica headers de CSRF
            csrf_headers = ["x-csrf-token", "x-xsrf-token"]
            for header in csrf_headers:
                if header in response.headers:
                    return {
                        "detectado": True,
                        "tipo": "CSRF Protection",
                        "evidencia": f"Header CSRF encontrado: {header}",
                        "confianca": 0.9
                    }
        
        except Exception:
            pass
        
        return {"detectado": False}
    
    def _testar_ip_blocking(self):
        """Testa para bloqueio por IP"""
        try:
            # Testa com headers de IP falsos
            fake_ips = [
                "127.0.0.1", "192.168.1.1", "10.0.0.1",
                "8.8.8.8", "1.1.1.1"
            ]
            
            for fake_ip in fake_ips:
                headers = {
                    "X-Forwarded-For": fake_ip,
                    "X-Real-IP": fake_ip,
                    "X-Originating-IP": fake_ip
                }
                
                response = self.session.get(self.target_url, headers=headers, timeout=10)
                
                # Se conseguir acessar com IP falso mas não sem ele
                if response.status_code == 200:
                    response_normal = self.session.get(self.target_url, timeout=10)
                    if response_normal.status_code != 200:
                        return {
                            "detectado": True,
                            "tipo": "IP Blocking",
                            "evidencia": f"Acesso permitido apenas com IP falso: {fake_ip}",
                            "confianca": 0.7
                        }
        
        except Exception:
            pass
        
        return {"detectado": False}
    
    def detectar_todas_defesas(self):
        """Executa todos os testes de detecção de defesas"""
        print(f"[defense_detector] 🛡️ Detectando defesas em: {self.target_url}")
        
        testes = [
            ("Cloudflare WAF", self._testar_waf_cloudflare),
            ("AWS WAF", self._testar_waf_aws),
            ("Sucuri WAF", self._testar_waf_sucuri),
            ("Incapsula WAF", self._testar_waf_incapsula),
            ("Rate Limiting", self._testar_rate_limiting),
            ("CAPTCHA", self._testar_captcha),
            ("CSRF Protection", self._testar_csrf_protection),
            ("IP Blocking", self._testar_ip_blocking)
        ]
        
        defesas_encontradas = []
        
        for nome_teste, funcao_teste in testes:
            try:
                print(f"[defense_detector] 🔍 Testando: {nome_teste}")
                resultado = funcao_teste()
                
                if resultado.get("detectado"):
                    defesas_encontradas.append({
                        "nome": nome_teste,
                        "tipo": resultado["tipo"],
                        "evidencia": resultado["evidencia"],
                        "confianca": resultado["confianca"],
                        "detalhes": resultado.get("detalhes", {}),
                        "timestamp": datetime.now().isoformat()
                    })
                    print(f"[defense_detector] 🚨 {resultado['tipo']} detectado! (confiança: {resultado['confianca']:.1%})")
                
                # Delay entre testes para evitar detecção
                time.sleep(random.uniform(1, 3))
                
            except Exception as e:
                print(f"[defense_detector] ⚠️ Erro no teste {nome_teste}: {str(e)}")
                continue
        
        return {
            "target_url": self.target_url,
            "timestamp": datetime.now().isoformat(),
            "defesas_detectadas": defesas_encontradas,
            "total_defesas": len(defesas_encontradas),
            "nivel_protecao": self._calcular_nivel_protecao(defesas_encontradas),
            "recomendacoes_bypass": self._gerar_recomendacoes_bypass(defesas_encontradas)
        }
    
    def _calcular_nivel_protecao(self, defesas):
        """Calcula nível de proteção baseado nas defesas detectadas"""
        if not defesas:
            return "BAIXO"
        
        score = 0
        for defesa in defesas:
            if "WAF" in defesa["tipo"]:
                score += 3
            elif defesa["tipo"] in ["Rate Limiting", "CAPTCHA"]:
                score += 2
            else:
                score += 1
        
        if score >= 6:
            return "MUITO ALTO"
        elif score >= 4:
            return "ALTO"
        elif score >= 2:
            return "MÉDIO"
        else:
            return "BAIXO"
    
    def _gerar_recomendacoes_bypass(self, defesas):
        """Gera recomendações para bypass das defesas detectadas"""
        recomendacoes = []
        
        for defesa in defesas:
            if "Cloudflare" in defesa["tipo"]:
                recomendacoes.append("Usar rotação de User-Agents e IPs para bypass do Cloudflare")
                recomendacoes.append("Tentar bypass via subdominios não protegidos")
            
            elif "AWS WAF" in defesa["tipo"]:
                recomendacoes.append("Usar encoding de payloads para bypass do AWS WAF")
                recomendacoes.append("Tentar fragmentação de payloads")
            
            elif "Rate Limiting" in defesa["tipo"]:
                recomendacoes.append("Implementar delays maiores entre requisições")
                recomendacoes.append("Usar rotação de IPs e proxies")
            
            elif "CAPTCHA" in defesa["tipo"]:
                recomendacoes.append("Focar em endpoints que não requerem CAPTCHA")
                recomendacoes.append("Usar automação com resolução de CAPTCHA")
            
            elif "CSRF" in defesa["tipo"]:
                recomendacoes.append("Extrair tokens CSRF antes de ataques")
                recomendacoes.append("Verificar se proteção CSRF é consistente")
        
        return list(set(recomendacoes))  # Remove duplicatas

def executar(target_url):
    """Executa detecção completa de defesas"""
    print(f"[defense_detector] 🛡️ Iniciando detecção de defesas para: {target_url}")
    
    try:
        detector = DefenseDetector(target_url)
        resultado = detector.detectar_todas_defesas()
        
        # Salva resultado
        site_name = target_url.replace('https://', '').replace('http://', '').replace('/', '_')
        output_dir = f"output/{site_name}"
        os.makedirs(output_dir, exist_ok=True)
        
        arquivo_saida = f"{output_dir}/defense_analysis.json"
        with open(arquivo_saida, "w", encoding="utf-8") as f:
            json.dump(resultado, f, indent=4, ensure_ascii=False)
        
        print(f"[defense_detector] ✅ Detecção concluída")
        print(f"[defense_detector] 🛡️ Defesas detectadas: {resultado['total_defesas']}")
        print(f"[defense_detector] 📊 Nível de proteção: {resultado['nivel_protecao']}")
        print(f"[defense_detector] 💾 Resultado salvo em: {arquivo_saida}")
        
        return resultado
        
    except Exception as e:
        print(f"[defense_detector] ❌ Erro na detecção: {str(e)}")
        return {"erro": str(e)}

