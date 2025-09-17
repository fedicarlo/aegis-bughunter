"""
AEGIS Bug Hunter - Memory System
Sistema de memória e correlação para aprendizado contínuo
"""

import os
import json
import sqlite3
import hashlib
from datetime import datetime, timedelta
from urllib.parse import urlparse

class MemorySystem:
    def __init__(self, db_path="aegis_memory.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Inicializa o banco de dados SQLite"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Tabela de alvos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                domain TEXT NOT NULL,
                first_scan TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_scan TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_scans INTEGER DEFAULT 1,
                risk_level TEXT,
                technologies TEXT,
                defenses TEXT
            )
        ''')
        
        # Tabela de vulnerabilidades
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                vuln_type TEXT NOT NULL,
                location TEXT NOT NULL,
                payload TEXT NOT NULL,
                evidence TEXT,
                confidence REAL,
                severity TEXT,
                first_found TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_confirmed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active',
                false_positive BOOLEAN DEFAULT 0,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
        ''')
        
        # Tabela de payloads efetivos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS effective_payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload TEXT NOT NULL,
                payload_type TEXT NOT NULL,
                target_domain TEXT NOT NULL,
                success_rate REAL DEFAULT 0.0,
                times_used INTEGER DEFAULT 1,
                times_successful INTEGER DEFAULT 0,
                last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                context TEXT
            )
        ''')
        
        # Tabela de defesas detectadas
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detected_defenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                defense_type TEXT NOT NULL,
                defense_name TEXT NOT NULL,
                confidence REAL,
                bypass_methods TEXT,
                first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                active BOOLEAN DEFAULT 1,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
        ''')
        
        # Tabela de padrões de sucesso
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS success_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_type TEXT NOT NULL,
                pattern_data TEXT NOT NULL,
                success_count INTEGER DEFAULT 1,
                total_attempts INTEGER DEFAULT 1,
                effectiveness REAL DEFAULT 0.0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tabela de sessões de scan
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                session_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                session_end TIMESTAMP,
                modules_executed TEXT,
                vulnerabilities_found INTEGER DEFAULT 0,
                scan_duration INTEGER,
                success_rate REAL DEFAULT 0.0,
                FOREIGN KEY (target_id) REFERENCES targets (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def get_target_id(self, target_url):
        """Obtém ou cria ID do alvo"""
        domain = urlparse(target_url).netloc
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Verifica se alvo já existe
        cursor.execute("SELECT id FROM targets WHERE url = ?", (target_url,))
        result = cursor.fetchone()
        
        if result:
            target_id = result[0]
            # Atualiza última varredura
            cursor.execute(
                "UPDATE targets SET last_scan = CURRENT_TIMESTAMP, total_scans = total_scans + 1 WHERE id = ?",
                (target_id,)
            )
        else:
            # Cria novo alvo
            cursor.execute(
                "INSERT INTO targets (url, domain) VALUES (?, ?)",
                (target_url, domain)
            )
            target_id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        return target_id
    
    def store_vulnerabilities(self, target_url, vulnerabilities):
        """Armazena vulnerabilidades encontradas"""
        target_id = self.get_target_id(target_url)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for vuln in vulnerabilities:
            # Verifica se vulnerabilidade já existe
            vuln_hash = hashlib.md5(
                f"{vuln.get('tipo_payload', vuln.get('tipo', ''))}{vuln.get('localizacao', vuln.get('parametro', ''))}{vuln.get('payload', '')}".encode()
            ).hexdigest()
            
            cursor.execute(
                "SELECT id FROM vulnerabilities WHERE target_id = ? AND vuln_type = ? AND location = ? AND payload = ?",
                (target_id, vuln.get('tipo_payload', vuln.get('tipo', '')), 
                 vuln.get('localizacao', vuln.get('parametro', '')), vuln.get('payload', ''))
            )
            
            if cursor.fetchone():
                # Atualiza vulnerabilidade existente
                cursor.execute(
                    "UPDATE vulnerabilities SET last_confirmed = CURRENT_TIMESTAMP, confidence = ? WHERE target_id = ? AND vuln_type = ? AND location = ? AND payload = ?",
                    (vuln.get('confianca', 0.5), target_id, vuln.get('tipo_payload', vuln.get('tipo', '')),
                     vuln.get('localizacao', vuln.get('parametro', '')), vuln.get('payload', ''))
                )
            else:
                # Insere nova vulnerabilidade
                cursor.execute(
                    "INSERT INTO vulnerabilities (target_id, vuln_type, location, payload, evidence, confidence, severity) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (target_id, vuln.get('tipo_payload', vuln.get('tipo', '')),
                     vuln.get('localizacao', vuln.get('parametro', '')), vuln.get('payload', ''),
                     vuln.get('evidencia', ''), vuln.get('confianca', 0.5),
                     self._classify_severity(vuln.get('tipo_payload', vuln.get('tipo', ''))))
                )
        
        conn.commit()
        conn.close()
    
    def store_effective_payload(self, payload, payload_type, target_url, success=True, context=""):
        """Armazena payload efetivo"""
        domain = urlparse(target_url).netloc
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Verifica se payload já existe para este domínio
        cursor.execute(
            "SELECT id, times_used, times_successful FROM effective_payloads WHERE payload = ? AND payload_type = ? AND target_domain = ?",
            (payload, payload_type, domain)
        )
        result = cursor.fetchone()
        
        if result:
            payload_id, times_used, times_successful = result
            new_times_used = times_used + 1
            new_times_successful = times_successful + (1 if success else 0)
            new_success_rate = new_times_successful / new_times_used
            
            cursor.execute(
                "UPDATE effective_payloads SET times_used = ?, times_successful = ?, success_rate = ?, last_used = CURRENT_TIMESTAMP WHERE id = ?",
                (new_times_used, new_times_successful, new_success_rate, payload_id)
            )
        else:
            success_rate = 1.0 if success else 0.0
            cursor.execute(
                "INSERT INTO effective_payloads (payload, payload_type, target_domain, success_rate, times_successful, context) VALUES (?, ?, ?, ?, ?, ?)",
                (payload, payload_type, domain, success_rate, 1 if success else 0, context)
            )
        
        conn.commit()
        conn.close()
    
    def store_defenses(self, target_url, defenses):
        """Armazena defesas detectadas"""
        target_id = self.get_target_id(target_url)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for defense in defenses:
            # Verifica se defesa já foi detectada
            cursor.execute(
                "SELECT id FROM detected_defenses WHERE target_id = ? AND defense_type = ? AND defense_name = ?",
                (target_id, defense.get('nome', ''), defense.get('tipo', ''))
            )
            
            if cursor.fetchone():
                # Atualiza detecção existente
                cursor.execute(
                    "UPDATE detected_defenses SET last_detected = CURRENT_TIMESTAMP, confidence = ? WHERE target_id = ? AND defense_type = ? AND defense_name = ?",
                    (defense.get('confianca', 0.5), target_id, defense.get('nome', ''), defense.get('tipo', ''))
                )
            else:
                # Insere nova detecção
                cursor.execute(
                    "INSERT INTO detected_defenses (target_id, defense_type, defense_name, confidence) VALUES (?, ?, ?, ?)",
                    (target_id, defense.get('nome', ''), defense.get('tipo', ''), defense.get('confianca', 0.5))
                )
        
        conn.commit()
        conn.close()
    
    def get_historical_vulnerabilities(self, target_url):
        """Obtém vulnerabilidades históricas do alvo"""
        target_id = self.get_target_id(target_url)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT vuln_type, location, payload, evidence, confidence, severity, first_found, status FROM vulnerabilities WHERE target_id = ? AND status = 'active'",
            (target_id,)
        )
        
        vulnerabilities = []
        for row in cursor.fetchall():
            vulnerabilities.append({
                "tipo": row[0],
                "localizacao": row[1],
                "payload": row[2],
                "evidencia": row[3],
                "confianca": row[4],
                "severidade": row[5],
                "primeira_deteccao": row[6],
                "status": row[7]
            })
        
        conn.close()
        return vulnerabilities
    
    def get_best_payloads(self, payload_type, target_url=None, limit=10):
        """Obtém melhores payloads para um tipo específico"""
        domain = urlparse(target_url).netloc if target_url else None
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if domain:
            cursor.execute(
                "SELECT payload, success_rate, times_used, context FROM effective_payloads WHERE payload_type = ? AND target_domain = ? ORDER BY success_rate DESC, times_used DESC LIMIT ?",
                (payload_type, domain, limit)
            )
        else:
            cursor.execute(
                "SELECT payload, success_rate, times_used, context FROM effective_payloads WHERE payload_type = ? ORDER BY success_rate DESC, times_used DESC LIMIT ?",
                (payload_type, limit)
            )
        
        payloads = []
        for row in cursor.fetchall():
            payloads.append({
                "payload": row[0],
                "success_rate": row[1],
                "times_used": row[2],
                "context": row[3]
            })
        
        conn.close()
        return payloads
    
    def get_defense_history(self, target_url):
        """Obtém histórico de defesas do alvo"""
        target_id = self.get_target_id(target_url)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT defense_type, defense_name, confidence, first_detected, last_detected, active FROM detected_defenses WHERE target_id = ?",
            (target_id,)
        )
        
        defenses = []
        for row in cursor.fetchall():
            defenses.append({
                "tipo": row[0],
                "nome": row[1],
                "confianca": row[2],
                "primeira_deteccao": row[3],
                "ultima_deteccao": row[4],
                "ativo": bool(row[5])
            })
        
        conn.close()
        return defenses
    
    def analyze_target_patterns(self, target_url):
        """Analisa padrões do alvo baseado no histórico"""
        domain = urlparse(target_url).netloc
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Análise de vulnerabilidades mais comuns
        cursor.execute(
            "SELECT vuln_type, COUNT(*) as count FROM vulnerabilities v JOIN targets t ON v.target_id = t.id WHERE t.domain = ? GROUP BY vuln_type ORDER BY count DESC",
            (domain,)
        )
        vuln_patterns = cursor.fetchall()
        
        # Análise de payloads mais efetivos
        cursor.execute(
            "SELECT payload_type, AVG(success_rate) as avg_success FROM effective_payloads WHERE target_domain = ? GROUP BY payload_type ORDER BY avg_success DESC",
            (domain,)
        )
        payload_patterns = cursor.fetchall()
        
        # Análise de defesas
        cursor.execute(
            "SELECT defense_type, COUNT(*) as count FROM detected_defenses d JOIN targets t ON d.target_id = t.id WHERE t.domain = ? AND d.active = 1 GROUP BY defense_type",
            (domain,)
        )
        defense_patterns = cursor.fetchall()
        
        conn.close()
        
        return {
            "vulnerabilidades_comuns": [{"tipo": row[0], "frequencia": row[1]} for row in vuln_patterns],
            "payloads_efetivos": [{"tipo": row[0], "taxa_sucesso": row[1]} for row in payload_patterns],
            "defesas_ativas": [{"tipo": row[0], "frequencia": row[1]} for row in defense_patterns]
        }
    
    def generate_recommendations(self, target_url):
        """Gera recomendações baseadas no histórico"""
        patterns = self.analyze_target_patterns(target_url)
        historical_vulns = self.get_historical_vulnerabilities(target_url)
        defense_history = self.get_defense_history(target_url)
        
        recommendations = {
            "payloads_recomendados": {},
            "areas_foco": [],
            "estrategias_bypass": [],
            "vulnerabilidades_recorrentes": []
        }
        
        # Recomenda payloads baseado no histórico
        for pattern in patterns["payloads_efetivos"]:
            if pattern["taxa_sucesso"] > 0.5:
                best_payloads = self.get_best_payloads(pattern["tipo"], target_url, 5)
                recommendations["payloads_recomendados"][pattern["tipo"]] = best_payloads
        
        # Identifica áreas de foco
        for pattern in patterns["vulnerabilidades_comuns"]:
            if pattern["frequencia"] > 1:
                recommendations["areas_foco"].append(f"Focar em {pattern['tipo']} (encontrado {pattern['frequencia']} vezes)")
        
        # Estratégias de bypass baseadas nas defesas
        for defense in defense_history:
            if defense["ativo"]:
                if "WAF" in defense["nome"]:
                    recommendations["estrategias_bypass"].append(f"Usar encoding para bypass de {defense['nome']}")
                elif "Rate Limiting" in defense["nome"]:
                    recommendations["estrategias_bypass"].append("Implementar delays maiores entre requisições")
        
        # Vulnerabilidades recorrentes
        for vuln in historical_vulns:
            if vuln["confianca"] > 0.8:
                recommendations["vulnerabilidades_recorrentes"].append({
                    "tipo": vuln["tipo"],
                    "localizacao": vuln["localizacao"],
                    "confianca": vuln["confianca"]
                })
        
        return recommendations
    
    def _classify_severity(self, vuln_type):
        """Classifica severidade da vulnerabilidade"""
        severity_map = {
            "sql_injection": "CRITICAL",
            "command_injection": "CRITICAL",
            "xss": "HIGH",
            "file_inclusion": "HIGH",
            "header_injection": "MEDIUM"
        }
        return severity_map.get(vuln_type, "LOW")
    
    def get_statistics(self):
        """Obtém estatísticas gerais do sistema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total de alvos
        cursor.execute("SELECT COUNT(*) FROM targets")
        total_targets = cursor.fetchone()[0]
        
        # Total de vulnerabilidades
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status = 'active'")
        total_vulns = cursor.fetchone()[0]
        
        # Vulnerabilidades por severidade
        cursor.execute("SELECT severity, COUNT(*) FROM vulnerabilities WHERE status = 'active' GROUP BY severity")
        vulns_by_severity = dict(cursor.fetchall())
        
        # Payloads mais efetivos
        cursor.execute("SELECT payload_type, AVG(success_rate) FROM effective_payloads GROUP BY payload_type ORDER BY AVG(success_rate) DESC LIMIT 5")
        top_payloads = cursor.fetchall()
        
        # Defesas mais comuns
        cursor.execute("SELECT defense_type, COUNT(*) FROM detected_defenses WHERE active = 1 GROUP BY defense_type ORDER BY COUNT(*) DESC LIMIT 5")
        common_defenses = cursor.fetchall()
        
        conn.close()
        
        return {
            "total_targets": total_targets,
            "total_vulnerabilities": total_vulns,
            "vulnerabilities_by_severity": vulns_by_severity,
            "top_payload_types": [{"tipo": row[0], "taxa_sucesso": row[1]} for row in top_payloads],
            "common_defenses": [{"tipo": row[0], "frequencia": row[1]} for row in common_defenses]
        }

def executar(target_url):
    """Executa sistema de memória e correlação"""
    print(f"[memory_system] 🧠 Analisando memória e correlações para: {target_url}")
    
    try:
        memory = MemorySystem()
        
        # Carrega dados dos módulos anteriores
        site_name = target_url.replace('https://', '').replace('http://', '').replace('/', '_')
        output_dir = f"output/{site_name}"
        
        # Processa vulnerabilidades se existirem
        injects_file = f"{output_dir}/injects.json"
        if os.path.exists(injects_file):
            with open(injects_file, 'r', encoding='utf-8') as f:
                injects_data = json.load(f)
                if "vulnerabilidades_encontradas" in injects_data:
                    memory.store_vulnerabilities(target_url, injects_data["vulnerabilidades_encontradas"])
        
        # Processa defesas se existirem
        defense_file = f"{output_dir}/defense_analysis.json"
        if os.path.exists(defense_file):
            with open(defense_file, 'r', encoding='utf-8') as f:
                defense_data = json.load(f)
                if "defesas_detectadas" in defense_data:
                    memory.store_defenses(target_url, defense_data["defesas_detectadas"])
        
        # Gera análises e recomendações
        patterns = memory.analyze_target_patterns(target_url)
        recommendations = memory.generate_recommendations(target_url)
        historical_vulns = memory.get_historical_vulnerabilities(target_url)
        defense_history = memory.get_defense_history(target_url)
        statistics = memory.get_statistics()
        
        resultado = {
            "target_url": target_url,
            "timestamp": datetime.now().isoformat(),
            "padroes_identificados": patterns,
            "recomendacoes": recommendations,
            "historico_vulnerabilidades": historical_vulns,
            "historico_defesas": defense_history,
            "estatisticas_gerais": statistics,
            "resumo": {
                "total_vulnerabilidades_historicas": len(historical_vulns),
                "total_defesas_ativas": len([d for d in defense_history if d["ativo"]]),
                "tipos_payload_efetivos": len(recommendations["payloads_recomendados"]),
                "areas_foco_identificadas": len(recommendations["areas_foco"])
            }
        }
        
        # Salva resultado
        arquivo_saida = f"{output_dir}/memory_analysis.json"
        with open(arquivo_saida, "w", encoding="utf-8") as f:
            json.dump(resultado, f, indent=4, ensure_ascii=False)
        
        print(f"[memory_system] ✅ Análise de memória concluída")
        print(f"[memory_system] 📊 Vulnerabilidades históricas: {len(historical_vulns)}")
        print(f"[memory_system] 🛡️ Defesas ativas: {len([d for d in defense_history if d['ativo']])}")
        print(f"[memory_system] 🎯 Áreas de foco: {len(recommendations['areas_foco'])}")
        print(f"[memory_system] 💾 Resultado salvo em: {arquivo_saida}")
        
        return resultado
        
    except Exception as e:
        print(f"[memory_system] ❌ Erro na análise de memória: {str(e)}")
        return {"erro": str(e)}

