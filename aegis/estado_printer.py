"""
AEGIS Bug Hunter - Estado Printer
Módulo responsável por exibir o estado atual da análise
"""

import os
import json
from datetime import datetime

def exibir_banner_status():
    """Exibe banner de status do sistema"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                    📊 STATUS DO SISTEMA 📊                    ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def verificar_status_modulos(site_name):
    """Verifica status de execução dos módulos"""
    output_dir = f"output/{site_name}"
    
    modulos_status = {
        "pre_recon": {"arquivo": "pre_recon.json", "status": "❌", "dados": None},
        "headers_analysis": {"arquivo": "headers_analysis.json", "status": "❌", "dados": None},
        "parser": {"arquivo": "parser.json", "status": "❌", "dados": None},
        "injects": {"arquivo": "injects.json", "status": "❌", "dados": None},
        "relatorio_final": {"arquivo": "relatorio_final.json", "status": "❌", "dados": None}
    }
    
    if not os.path.exists(output_dir):
        return modulos_status
    
    for modulo, info in modulos_status.items():
        arquivo_path = f"{output_dir}/{info['arquivo']}"
        if os.path.exists(arquivo_path):
            try:
                with open(arquivo_path, 'r', encoding='utf-8') as f:
                    dados = json.load(f)
                    if "erro" not in dados:
                        info["status"] = "✅"
                        info["dados"] = dados
                    else:
                        info["status"] = "⚠️"
            except:
                info["status"] = "⚠️"
    
    return modulos_status

def exibir_progresso_analise(modulos_status):
    """Exibe progresso da análise"""
    print("📋 PROGRESSO DA ANÁLISE:")
    print("-" * 50)
    
    for modulo, info in modulos_status.items():
        nome_formatado = modulo.replace("_", " ").title()
        print(f"{info['status']} {nome_formatado}")
    
    # Calcula percentual de conclusão
    total_modulos = len(modulos_status)
    modulos_concluidos = sum(1 for info in modulos_status.values() if info["status"] == "✅")
    percentual = (modulos_concluidos / total_modulos) * 100
    
    print("-" * 50)
    print(f"📊 Progresso: {modulos_concluidos}/{total_modulos} ({percentual:.1f}%)")
    
    return percentual

def exibir_estatisticas_rapidas(modulos_status):
    """Exibe estatísticas rápidas dos resultados"""
    print("\n📈 ESTATÍSTICAS RÁPIDAS:")
    print("-" * 50)
    
    # Estatísticas do pre_recon
    if modulos_status["pre_recon"]["status"] == "✅":
        dados = modulos_status["pre_recon"]["dados"]
        resumo = dados.get("resumo", {})
        print(f"🌐 Servidor: {resumo.get('servidor', 'Desconhecido')}")
        print(f"🔒 SSL: {'Sim' if resumo.get('tem_ssl') else 'Não'}")
        print(f"🛡️ WAF: {'Detectado' if resumo.get('tem_waf') else 'Não detectado'}")
        print(f"🚪 Portas abertas: {resumo.get('portas_encontradas', 0)}")
    
    # Estatísticas do headers_analysis
    if modulos_status["headers_analysis"]["status"] == "✅":
        dados = modulos_status["headers_analysis"]["dados"]
        score = dados.get("score_seguranca", {})
        print(f"🔐 Score de segurança: {score.get('percentual', 0)}% ({score.get('nivel', 'N/A')})")
        wafs = dados.get("wafs_detectados", [])
        if wafs:
            print(f"🛡️ WAFs detectados: {', '.join(wafs)}")
    
    # Estatísticas do parser
    if modulos_status["parser"]["status"] == "✅":
        dados = modulos_status["parser"]["dados"]
        resumo = dados.get("resumo", {})
        print(f"📝 Formulários: {len(dados.get('formularios', []))}")
        print(f"🔗 Links: {dados.get('links', {}).get('total', 0)}")
        print(f"📜 Scripts: {len(dados.get('scripts', []))}")
    
    # Estatísticas de vulnerabilidades
    if modulos_status["injects"]["status"] == "✅":
        dados = modulos_status["injects"]["dados"]
        total_vulns = dados.get("total_vulnerabilidades", 0)
        tipos = dados.get("tipos_encontrados", [])
        print(f"🚨 Vulnerabilidades: {total_vulns}")
        if tipos:
            print(f"📋 Tipos encontrados: {', '.join(tipos)}")

def exibir_alertas_importantes(modulos_status):
    """Exibe alertas importantes baseados nos resultados"""
    alertas = []
    
    # Verifica vulnerabilidades críticas
    if modulos_status["injects"]["status"] == "✅":
        dados = modulos_status["injects"]["dados"]
        vulns = dados.get("vulnerabilidades_encontradas", [])
        
        vulns_criticas = [v for v in vulns if v.get("tipo_injecao") in ["sql_injection", "command_injection"]]
        if vulns_criticas:
            alertas.append(f"🚨 CRÍTICO: {len(vulns_criticas)} vulnerabilidades críticas encontradas!")
    
    # Verifica ausência de SSL
    if modulos_status["pre_recon"]["status"] == "✅":
        dados = modulos_status["pre_recon"]["dados"]
        if not dados.get("resumo", {}).get("tem_ssl", False):
            alertas.append("⚠️ ATENÇÃO: SSL/TLS não habilitado!")
    
    # Verifica score de segurança baixo
    if modulos_status["headers_analysis"]["status"] == "✅":
        dados = modulos_status["headers_analysis"]["dados"]
        score = dados.get("score_seguranca", {}).get("percentual", 0)
        if score < 50:
            alertas.append(f"⚠️ ATENÇÃO: Score de segurança baixo ({score}%)!")
    
    if alertas:
        print("\n🚨 ALERTAS IMPORTANTES:")
        print("-" * 50)
        for alerta in alertas:
            print(alerta)

def exibir_proximos_passos(percentual_conclusao):
    """Exibe próximos passos baseado no progresso"""
    print("\n🎯 PRÓXIMOS PASSOS:")
    print("-" * 50)
    
    if percentual_conclusao < 100:
        print("⏳ Aguarde a conclusão de todos os módulos")
        print("📊 Execute novamente para ver o status atualizado")
    else:
        print("✅ Análise completa!")
        print("📄 Verifique o relatório final gerado")
        print("🔍 Revise as vulnerabilidades encontradas")
        print("🛠️ Implemente as correções recomendadas")

def gerar_resumo_arquivo(target_url, modulos_status, output_dir):
    """Gera arquivo de resumo do status"""
    resumo = {
        "target_url": target_url,
        "timestamp": datetime.now().isoformat(),
        "status_modulos": {},
        "estatisticas": {
            "modulos_concluidos": 0,
            "modulos_com_erro": 0,
            "percentual_conclusao": 0
        }
    }
    
    for modulo, info in modulos_status.items():
        resumo["status_modulos"][modulo] = {
            "status": info["status"],
            "arquivo": info["arquivo"],
            "concluido": info["status"] == "✅"
        }
        
        if info["status"] == "✅":
            resumo["estatisticas"]["modulos_concluidos"] += 1
        elif info["status"] == "⚠️":
            resumo["estatisticas"]["modulos_com_erro"] += 1
    
    total_modulos = len(modulos_status)
    resumo["estatisticas"]["percentual_conclusao"] = (
        resumo["estatisticas"]["modulos_concluidos"] / total_modulos
    ) * 100
    
    # Salva arquivo de status
    arquivo_status = f"{output_dir}/status_analise.json"
    with open(arquivo_status, "w", encoding="utf-8") as f:
        json.dump(resumo, f, indent=4, ensure_ascii=False)
    
    return arquivo_status

def executar(target_url):
    """Executa exibição do estado atual da análise"""
    print(f"[estado_printer] 📊 Exibindo status da análise para: {target_url}")
    
    try:
        site_name = target_url.replace("https://", "").replace("http://", "").replace("/", "_")
        output_dir = f"output/{site_name}"
        
        # Exibe banner
        exibir_banner_status()
        
        # Verifica status dos módulos
        modulos_status = verificar_status_modulos(site_name)
        
        # Exibe progresso
        percentual = exibir_progresso_analise(modulos_status)
        
        # Exibe estatísticas
        exibir_estatisticas_rapidas(modulos_status)
        
        # Exibe alertas
        exibir_alertas_importantes(modulos_status)
        
        # Exibe próximos passos
        exibir_proximos_passos(percentual)
        
        # Gera arquivo de resumo
        if os.path.exists(output_dir):
            arquivo_status = gerar_resumo_arquivo(target_url, modulos_status, output_dir)
            print(f"\n💾 Status salvo em: {arquivo_status}")
        
        print(f"\n[estado_printer] ✅ Status exibido com sucesso")
        
        return {
            "target_url": target_url,
            "percentual_conclusao": percentual,
            "modulos_status": modulos_status,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        print(f"[estado_printer] ❌ Erro ao exibir status: {str(e)}")
        return {"erro": str(e)}

