#!/usr/bin/env python3
"""
AEGIS Bug Hunter - Sistema Autônomo de Bug Bounty com IA
Arquivo principal de execução
"""

import os
import sys
import time
from datetime import datetime

# Adiciona o diretório aegis ao path
sys.path.append(os.path.join(os.path.dirname(__file__), 'aegis'))

from aegis import (
    agent_loop, 
    pre_recon, 
    estado_printer, 
    inject_finder, 
    parser, 
    report_gen, 
    reporter, 
    headers_analyzer,
    fuzzer,
    defense_detector,
    memory_system,
    ai_interpreter
)

def print_banner():
    """Exibe o banner do AEGIS"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                    🛡️  AEGIS BUG HUNTER 🛡️                    ║
    ║                                                               ║
    ║           Sistema Autônomo de Bug Bounty com IA              ║
    ║              "O hacker que nunca dorme"                      ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def log_execucao(mensagem):
    """Registra logs de execução"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file = "logs/execucao.log"
    
    os.makedirs("logs", exist_ok=True)
    
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {mensagem}\n")
    
    print(f"[{timestamp}] {mensagem}")

def executar_fluxo(target_url):
    """Executa o fluxo completo de análise do AEGIS"""
    log_execucao(f"🧠 Iniciando fluxo completo contra: {target_url}")
    
    # Lista de módulos na ordem de execução
    modulos = [
        ("agent_loop", agent_loop),
        ("pre_recon", pre_recon),
        ("headers_analyzer", headers_analyzer),
        ("parser", parser),
        ("inject_finder", inject_finder),
        ("fuzzer", fuzzer),
        ("defense_detector", defense_detector),
        ("memory_system", memory_system),
        ("ai_interpreter", ai_interpreter),
        ("estado_printer", estado_printer),
        ("report_gen", report_gen),
        ("reporter", reporter)
    ]
    
    resultados = {}
    
    for nome_modulo, modulo in modulos:
        try:
            log_execucao(f"➡️ Executando módulo: {nome_modulo}")
            
            if hasattr(modulo, "executar"):
                inicio = time.time()
                resultado = modulo.executar(target_url)
                fim = time.time()
                
                resultados[nome_modulo] = {
                    "status": "sucesso",
                    "tempo_execucao": round(fim - inicio, 2),
                    "resultado": resultado
                }
                
                log_execucao(f"✅ Módulo '{nome_modulo}' executado com sucesso ({resultados[nome_modulo]['tempo_execucao']}s)")
            else:
                log_execucao(f"⚠️ Módulo '{nome_modulo}' não possui a função 'executar'")
                resultados[nome_modulo] = {
                    "status": "erro",
                    "erro": "Função 'executar' não encontrada"
                }
                
        except Exception as e:
            log_execucao(f"❌ Falha ao executar '{nome_modulo}': {str(e)}")
            resultados[nome_modulo] = {
                "status": "erro",
                "erro": str(e)
            }
    
    log_execucao("🏁 Fluxo de execução finalizado")
    return resultados

def validar_url(url):
    """Valida se a URL fornecida é válida"""
    if not url:
        return False
    
    if not (url.startswith("http://") or url.startswith("https://")):
        return False
    
    return True

def main():
    """Função principal"""
    print_banner()
    
    try:
        # Solicita o alvo
        target = input("🌐 Digite o alvo para iniciar (ex: https://exemplo.com): ").strip()
        
        if not validar_url(target):
            print("❌ URL inválida! Use o formato: https://exemplo.com")
            return
        
        # Confirma a execução
        print(f"\n🎯 Alvo selecionado: {target}")
        confirmacao = input("Deseja continuar? (s/n): ").strip().lower()
        
        if confirmacao not in ['s', 'sim', 'y', 'yes']:
            print("🚫 Execução cancelada pelo usuário")
            return
        
        # Executa o fluxo
        print("\n" + "="*60)
        resultados = executar_fluxo(target)
        print("="*60)
        
        # Exibe resumo dos resultados
        print("\n📊 RESUMO DA EXECUÇÃO:")
        sucessos = sum(1 for r in resultados.values() if r["status"] == "sucesso")
        erros = len(resultados) - sucessos
        
        print(f"✅ Módulos executados com sucesso: {sucessos}")
        print(f"❌ Módulos com erro: {erros}")
        
        if erros > 0:
            print("\n🔍 Módulos com erro:")
            for nome, resultado in resultados.items():
                if resultado["status"] == "erro":
                    print(f"  - {nome}: {resultado['erro']}")
        
        print(f"\n📁 Resultados salvos em: output/{target.replace('https://', '').replace('http://', '')}/")
        print("📋 Logs de execução salvos em: logs/execucao.log")
        
    except KeyboardInterrupt:
        print("\n\n🛑 Execução interrompida pelo usuário")
    except Exception as e:
        print(f"\n❌ Erro inesperado: {str(e)}")
        log_execucao(f"Erro inesperado: {str(e)}")

if __name__ == "__main__":
    main()

