"""
AEGIS Bug Hunter - Configuration Manager
Módulo responsável pelo gerenciamento de configurações
"""

import os
import json
from datetime import datetime

class ConfigManager:
    def __init__(self, config_file="config/aegis_config.json"):
        self.config_file = config_file
        self.config = {}
        self.load_config()
    
    def load_config(self):
        """Carrega configuração do arquivo"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                print(f"[config_manager] ✅ Configuração carregada: {self.config_file}")
            else:
                print(f"[config_manager] ⚠️ Arquivo de configuração não encontrado: {self.config_file}")
                self.config = self._get_default_config()
                self.save_config()
        except Exception as e:
            print(f"[config_manager] ❌ Erro ao carregar configuração: {str(e)}")
            self.config = self._get_default_config()
    
    def save_config(self):
        """Salva configuração no arquivo"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
            print(f"[config_manager] ✅ Configuração salva: {self.config_file}")
        except Exception as e:
            print(f"[config_manager] ❌ Erro ao salvar configuração: {str(e)}")
    
    def get(self, key_path, default=None):
        """Obtém valor da configuração usando notação de ponto"""
        keys = key_path.split('.')
        value = self.config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path, value):
        """Define valor na configuração usando notação de ponto"""
        keys = key_path.split('.')
        config_ref = self.config
        
        try:
            for key in keys[:-1]:
                if key not in config_ref:
                    config_ref[key] = {}
                config_ref = config_ref[key]
            
            config_ref[keys[-1]] = value
            return True
        except Exception as e:
            print(f"[config_manager] ❌ Erro ao definir configuração: {str(e)}")
            return False
    
    def get_scanning_config(self):
        """Obtém configurações de scanning"""
        return {
            "timeout": self.get("scanning.default_timeout", 10),
            "max_threads": self.get("scanning.max_threads", 5),
            "delay_min": self.get("scanning.delay_between_requests.min", 0.5),
            "delay_max": self.get("scanning.delay_between_requests.max", 2.0),
            "retry_attempts": self.get("scanning.retry_attempts", 3),
            "user_agent_rotation": self.get("scanning.user_agent_rotation", True),
            "stealth_mode": self.get("scanning.stealth_mode", True)
        }
    
    def get_fuzzing_config(self):
        """Obtém configurações de fuzzing"""
        return {
            "enabled": self.get("fuzzing.enabled", True),
            "max_payloads_per_type": self.get("fuzzing.max_payloads_per_type", 10),
            "adaptive_delays": self.get("fuzzing.adaptive_delays", True),
            "payload_encoding": self.get("fuzzing.payload_encoding", True),
            "waf_bypass_techniques": self.get("fuzzing.waf_bypass_techniques", True)
        }
    
    def get_ai_config(self):
        """Obtém configurações de IA"""
        return {
            "enabled": self.get("ai_interpreter.enabled", True),
            "use_openai": self.get("ai_interpreter.use_openai", True),
            "fallback_to_local": self.get("ai_interpreter.fallback_to_local", True),
            "model": self.get("ai_interpreter.model", "gpt-3.5-turbo"),
            "max_tokens": self.get("ai_interpreter.max_tokens", 1000),
            "temperature": self.get("ai_interpreter.temperature", 0.7)
        }
    
    def get_reporting_config(self):
        """Obtém configurações de relatórios"""
        return {
            "formats": self.get("reporting.formats", {}),
            "include_screenshots": self.get("reporting.include_screenshots", False),
            "detailed_payloads": self.get("reporting.detailed_payloads", True),
            "executive_summary": self.get("reporting.executive_summary", True),
            "technical_details": self.get("reporting.technical_details", True)
        }
    
    def get_memory_config(self):
        """Obtém configurações do sistema de memória"""
        return {
            "enabled": self.get("memory_system.enabled", True),
            "database_path": self.get("memory_system.database_path", "aegis_memory.db"),
            "store_payloads": self.get("memory_system.store_payloads", True),
            "store_vulnerabilities": self.get("memory_system.store_vulnerabilities", True),
            "store_defenses": self.get("memory_system.store_defenses", True),
            "cleanup_old_data": self.get("memory_system.cleanup_old_data", True),
            "retention_days": self.get("memory_system.retention_days", 90)
        }
    
    def get_notification_config(self):
        """Obtém configurações de notificações"""
        return {
            "email": self.get("integrations.notifications.email", {}),
            "webhook": self.get("integrations.notifications.webhook", {}),
            "slack": self.get("integrations.notifications.slack", {})
        }
    
    def is_module_enabled(self, module_name):
        """Verifica se um módulo está habilitado"""
        module_configs = {
            "fuzzer": "fuzzing.enabled",
            "defense_detector": "defense_detection.enabled",
            "memory_system": "memory_system.enabled",
            "ai_interpreter": "ai_interpreter.enabled"
        }
        
        if module_name in module_configs:
            return self.get(module_configs[module_name], True)
        
        return True  # Por padrão, módulos estão habilitados
    
    def update_last_scan(self, target_url):
        """Atualiza timestamp do último scan"""
        scans = self.get("recent_scans", [])
        
        # Remove scan anterior do mesmo alvo
        scans = [s for s in scans if s.get("target") != target_url]
        
        # Adiciona novo scan
        scans.append({
            "target": target_url,
            "timestamp": datetime.now().isoformat()
        })
        
        # Mantém apenas os 10 scans mais recentes
        scans = scans[-10:]
        
        self.set("recent_scans", scans)
        self.save_config()
    
    def get_recent_scans(self, limit=10):
        """Obtém scans recentes"""
        scans = self.get("recent_scans", [])
        return scans[-limit:]
    
    def _get_default_config(self):
        """Retorna configuração padrão"""
        return {
            "aegis_config": {
                "version": "1.0.0",
                "description": "Configuração padrão do AEGIS Bug Hunter",
                "created": datetime.now().isoformat()
            },
            "scanning": {
                "default_timeout": 10,
                "max_threads": 5,
                "delay_between_requests": {"min": 0.5, "max": 2.0},
                "retry_attempts": 3,
                "user_agent_rotation": True,
                "stealth_mode": True
            },
            "fuzzing": {
                "enabled": True,
                "max_payloads_per_type": 10,
                "adaptive_delays": True,
                "payload_encoding": True,
                "waf_bypass_techniques": True
            },
            "memory_system": {
                "enabled": True,
                "database_path": "aegis_memory.db",
                "store_payloads": True,
                "store_vulnerabilities": True,
                "store_defenses": True
            },
            "ai_interpreter": {
                "enabled": True,
                "use_openai": True,
                "fallback_to_local": True,
                "model": "gpt-3.5-turbo"
            },
            "reporting": {
                "formats": {
                    "json": True,
                    "markdown": True,
                    "pdf": False,
                    "html": False
                }
            }
        }

# Instância global do gerenciador de configuração
config_manager = ConfigManager()

def get_config():
    """Retorna instância global do gerenciador de configuração"""
    return config_manager

