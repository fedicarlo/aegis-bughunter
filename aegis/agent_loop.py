"""
AEGIS Bug Hunter - Agent Loop
Módulo responsável pelo loop principal de execução do agente
"""

import time
import random
from urllib.parse import urlparse

def gerar_user_agents():
    """Gera lista de user agents para rotação"""
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36"
    ]
    return user_agents

def analisar_alvo(target_url):
    """Analisa o alvo e extrai informações básicas"""
    parsed_url = urlparse(target_url)
    
    info_alvo = {
        "url_completa": target_url,
        "dominio": parsed_url.netloc,
        "esquema": parsed_url.scheme,
        "caminho": parsed_url.path,
        "parametros": parsed_url.params,
        "query": parsed_url.query,
        "fragmento": parsed_url.fragment,
        "porta": parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
    }
    
    return info_alvo

def configurar_sessao_ataque():
    """Configura parâmetros da sessão de ataque"""
    configuracao = {
        "user_agent": random.choice(gerar_user_agents()),
        "timeout": 10,
        "max_tentativas": 3,
        "delay_entre_requests": random.uniform(0.5, 2.0),
        "modo_stealth": True,
        "rotacao_headers": True
    }
    
    return configuracao

def executar(target_url):
    """Executa o loop principal do agente"""
    print(f"[agent_loop] 🤖 Iniciando loop de agente para: {target_url}")
    
    # Analisa o alvo
    info_alvo = analisar_alvo(target_url)
    print(f"[agent_loop] 🎯 Domínio alvo: {info_alvo['dominio']}")
    print(f"[agent_loop] 🔗 Porta: {info_alvo['porta']}")
    
    # Configura sessão de ataque
    config = configurar_sessao_ataque()
    print(f"[agent_loop] ⚙️ User-Agent selecionado: {config['user_agent'][:50]}...")
    print(f"[agent_loop] 🕐 Delay entre requests: {config['delay_entre_requests']:.2f}s")
    
    # Simula preparação do ambiente de ataque
    print(f"[agent_loop] 🔧 Preparando ambiente de ataque...")
    time.sleep(1)
    
    # Simula verificação de conectividade
    print(f"[agent_loop] 🌐 Verificando conectividade com o alvo...")
    time.sleep(0.5)
    
    # Simula configuração de proxies/rotação
    if config["modo_stealth"]:
        print(f"[agent_loop] 🥷 Modo stealth ativado")
    
    print(f"[agent_loop] ✅ Loop de agente configurado e pronto")
    
    resultado = {
        "info_alvo": info_alvo,
        "configuracao": config,
        "status": "configurado",
        "timestamp": time.time()
    }
    
    return resultado

def pausar_execucao(tempo_min=1, tempo_max=3):
    """Pausa a execução por um tempo aleatório para evitar detecção"""
    tempo_pausa = random.uniform(tempo_min, tempo_max)
    time.sleep(tempo_pausa)
    return tempo_pausa

def detectar_bloqueio(response_code, response_text=""):
    """Detecta se houve bloqueio ou rate limiting"""
    bloqueios_conhecidos = [
        429,  # Too Many Requests
        403,  # Forbidden
        503,  # Service Unavailable
        418,  # I'm a teapot (usado por alguns WAFs)
    ]
    
    if response_code in bloqueios_conhecidos:
        return True
    
    # Verifica por strings indicativas de bloqueio no conteúdo
    indicadores_bloqueio = [
        "cloudflare",
        "access denied",
        "blocked",
        "rate limit",
        "too many requests",
        "captcha"
    ]
    
    response_lower = response_text.lower()
    for indicador in indicadores_bloqueio:
        if indicador in response_lower:
            return True
    
    return False

