"""
AEGIS Bug Hunter - Report Generator
Módulo responsável pela geração de relatórios técnicos
"""

import os
import json
from datetime import datetime
import hashlib

def carregar_dados_modulos(site_name):
    """Carrega dados de todos os módulos executados"""
    output_dir = f"output/{site_name}"
    dados = {}
    
    arquivos_modulos = {
        "pre_recon": "pre_recon.json",
        "headers_analysis": "headers_analysis.json", 
        "parser": "parser.json",
        "injects": "injects.json"
    }
    
    for modulo, arquivo in arquivos_modulos.items():
        caminho_arquivo = f"{output_dir}/{arquivo}"
        if os.path.exists(caminho_arquivo):
            try:
                with open(caminho_arquivo, 'r', encoding='utf-8') as f:
                    dados[modulo] = json.load(f)
            except Exception as e:
                dados[modulo] = {"erro": f"Erro ao carregar {arquivo}: {str(e)}"}
        else:
            dados[modulo] = {"erro": f"Arquivo {arquivo} não encontrado"}
    
    return dados

def gerar_resumo_executivo(dados, target_url):
    """Gera resumo executivo do relatório"""
    resumo = {
        "alvo": target_url,
        "data_analise": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "status_geral": "CONCLUÍDO",
        "nivel_risco": "BAIXO",
        "vulnerabilidades_criticas": 0,
        "vulnerabilidades_altas": 0,
        "vulnerabilidades_medias": 0,
        "vulnerabilidades_baixas": 0,
        "total_vulnerabilidades": 0,
        "recomendacoes_prioritarias": []
    }
    
    # Analisa vulnerabilidades encontradas
    if "injects" in dados and "vulnerabilidades_encontradas" in dados["injects"]:
        vulns = dados["injects"]["vulnerabilidades_encontradas"]
        resumo["total_vulnerabilidades"] = len(vulns)
        
        # Classifica vulnerabilidades por severidade
        for vuln in vulns:
            tipo = vuln.get("tipo_injecao", vuln.get("tipo", ""))
            
            if tipo in ["sql_injection", "command_injection"]:
                resumo["vulnerabilidades_criticas"] += 1
            elif tipo in ["xss", "file_inclusion"]:
                resumo["vulnerabilidades_altas"] += 1
            elif tipo in ["header_injection"]:
                resumo["vulnerabilidades_medias"] += 1
            else:
                resumo["vulnerabilidades_baixas"] += 1
    
    # Define nível de risco geral
    if resumo["vulnerabilidades_criticas"] > 0:
        resumo["nivel_risco"] = "CRÍTICO"
    elif resumo["vulnerabilidades_altas"] > 0:
        resumo["nivel_risco"] = "ALTO"
    elif resumo["vulnerabilidades_medias"] > 0:
        resumo["nivel_risco"] = "MÉDIO"
    elif resumo["vulnerabilidades_baixas"] > 0:
        resumo["nivel_risco"] = "BAIXO"
    
    # Gera recomendações prioritárias
    if resumo["vulnerabilidades_criticas"] > 0:
        resumo["recomendacoes_prioritarias"].append("Corrigir imediatamente vulnerabilidades críticas de injeção")
    
    if "headers_analysis" in dados and "score_seguranca" in dados["headers_analysis"]:
        score = dados["headers_analysis"]["score_seguranca"]["percentual"]
        if score < 50:
            resumo["recomendacoes_prioritarias"].append("Implementar headers de segurança HTTP")
    
    if "pre_recon" in dados and "resumo" in dados["pre_recon"]:
        if not dados["pre_recon"]["resumo"].get("tem_ssl", False):
            resumo["recomendacoes_prioritarias"].append("Implementar certificado SSL/TLS")
    
    return resumo

def gerar_detalhes_tecnicos(dados):
    """Gera seção de detalhes técnicos"""
    detalhes = {
        "infraestrutura": {},
        "tecnologias": {},
        "seguranca": {},
        "vulnerabilidades_detalhadas": []
    }
    
    # Infraestrutura
    if "pre_recon" in dados and "resumo" in dados["pre_recon"]:
        detalhes["infraestrutura"] = {
            "servidor": dados["pre_recon"]["resumo"].get("servidor", "Desconhecido"),
            "ssl_habilitado": dados["pre_recon"]["resumo"].get("tem_ssl", False),
            "portas_abertas": dados["pre_recon"]["resumo"].get("portas_encontradas", 0),
            "waf_detectado": dados["pre_recon"]["resumo"].get("tem_waf", False)
        }
    
    # Tecnologias
    if "parser" in dados and "tecnologias" in dados["parser"]:
        detalhes["tecnologias"] = dados["parser"]["tecnologias"]
    
    # Segurança
    if "headers_analysis" in dados:
        headers_data = dados["headers_analysis"]
        detalhes["seguranca"] = {
            "score_headers": headers_data.get("score_seguranca", {}),
            "wafs_detectados": headers_data.get("wafs_detectados", []),
            "headers_seguranca": headers_data.get("headers_seguranca", {}),
            "metodos_http_perigosos": headers_data.get("resumo", {}).get("metodos_perigosos", [])
        }
    
    # Vulnerabilidades detalhadas
    if "injects" in dados and "vulnerabilidades_encontradas" in dados["injects"]:
        for vuln in dados["injects"]["vulnerabilidades_encontradas"]:
            vuln_detalhada = {
                "id": hashlib.md5(str(vuln).encode()).hexdigest()[:8],
                "tipo": vuln.get("tipo_injecao", vuln.get("tipo", "")),
                "severidade": classificar_severidade(vuln.get("tipo_injecao", vuln.get("tipo", ""))),
                "localizacao": vuln.get("parametro", vuln.get("header", vuln.get("form_action", ""))),
                "payload": vuln.get("payload", ""),
                "evidencia": vuln.get("evidencia", ""),
                "recomendacao": gerar_recomendacao(vuln.get("tipo_injecao", vuln.get("tipo", "")))
            }
            detalhes["vulnerabilidades_detalhadas"].append(vuln_detalhada)
    
    return detalhes

def classificar_severidade(tipo_vulnerabilidade):
    """Classifica severidade da vulnerabilidade"""
    severidades = {
        "sql_injection": "CRÍTICA",
        "command_injection": "CRÍTICA", 
        "xss": "ALTA",
        "file_inclusion": "ALTA",
        "header_injection": "MÉDIA",
        "ldap_injection": "ALTA",
        "xpath_injection": "ALTA",
        "nosql_injection": "CRÍTICA"
    }
    return severidades.get(tipo_vulnerabilidade, "BAIXA")

def gerar_recomendacao(tipo_vulnerabilidade):
    """Gera recomendação específica para o tipo de vulnerabilidade"""
    recomendacoes = {
        "sql_injection": "Implementar prepared statements e validação de entrada. Nunca concatenar dados do usuário diretamente em queries SQL.",
        "command_injection": "Validar e sanitizar todas as entradas do usuário. Evitar execução de comandos do sistema com dados não confiáveis.",
        "xss": "Implementar encoding/escaping adequado de saída. Usar Content Security Policy (CSP) e validação de entrada.",
        "file_inclusion": "Validar e restringir caminhos de arquivos. Implementar whitelist de arquivos permitidos.",
        "header_injection": "Validar e sanitizar dados antes de incluir em headers HTTP. Implementar encoding adequado.",
        "ldap_injection": "Usar prepared statements para LDAP. Validar e escapar caracteres especiais em queries LDAP.",
        "xpath_injection": "Usar prepared statements para XPath. Validar e escapar dados de entrada em expressões XPath.",
        "nosql_injection": "Validar tipos de dados e usar prepared statements. Evitar concatenação direta em queries NoSQL."
    }
    return recomendacoes.get(tipo_vulnerabilidade, "Implementar validação adequada de entrada e saída de dados.")

def gerar_relatorio_json(dados, target_url):
    """Gera relatório completo em formato JSON"""
    resumo = gerar_resumo_executivo(dados, target_url)
    detalhes = gerar_detalhes_tecnicos(dados)
    
    relatorio = {
        "metadata": {
            "versao_relatorio": "1.0",
            "gerado_por": "AEGIS Bug Hunter",
            "timestamp": datetime.now().isoformat(),
            "target": target_url,
            "hash_relatorio": ""
        },
        "resumo_executivo": resumo,
        "detalhes_tecnicos": detalhes,
        "dados_brutos": dados,
        "estatisticas": {
            "total_modulos_executados": len([k for k, v in dados.items() if "erro" not in v]),
            "total_testes_realizados": dados.get("injects", {}).get("total_testes", 0),
            "tempo_total_analise": "N/A"
        }
    }
    
    # Gera hash do relatório
    relatorio_str = json.dumps(relatorio, sort_keys=True)
    relatorio["metadata"]["hash_relatorio"] = hashlib.sha256(relatorio_str.encode()).hexdigest()[:16]
    
    return relatorio

def gerar_relatorio_markdown(relatorio):
    """Gera versão em Markdown do relatório"""
    resumo = relatorio["resumo_executivo"]
    detalhes = relatorio["detalhes_tecnicos"]
    
    md_content = f"""# Relatório de Segurança - AEGIS Bug Hunter

## Informações Gerais
- **Alvo:** {resumo['alvo']}
- **Data da Análise:** {resumo['data_analise']}
- **Status:** {resumo['status_geral']}
- **Nível de Risco:** {resumo['nivel_risco']}

## Resumo Executivo

### Vulnerabilidades Encontradas
- **Total:** {resumo['total_vulnerabilidades']}
- **Críticas:** {resumo['vulnerabilidades_criticas']}
- **Altas:** {resumo['vulnerabilidades_altas']}
- **Médias:** {resumo['vulnerabilidades_medias']}
- **Baixas:** {resumo['vulnerabilidades_baixas']}

### Recomendações Prioritárias
"""
    
    for rec in resumo['recomendacoes_prioritarias']:
        md_content += f"- {rec}\n"
    
    md_content += f"""
## Detalhes Técnicos

### Infraestrutura
- **Servidor:** {detalhes['infraestrutura'].get('servidor', 'N/A')}
- **SSL/TLS:** {'✅ Habilitado' if detalhes['infraestrutura'].get('ssl_habilitado') else '❌ Não habilitado'}
- **WAF Detectado:** {'✅ Sim' if detalhes['infraestrutura'].get('waf_detectado') else '❌ Não'}
- **Portas Abertas:** {detalhes['infraestrutura'].get('portas_abertas', 0)}

### Tecnologias Identificadas
"""
    
    tecnologias = detalhes.get('tecnologias', {})
    if tecnologias.get('frameworks'):
        md_content += f"- **Frameworks:** {', '.join(tecnologias['frameworks'])}\n"
    if tecnologias.get('bibliotecas'):
        md_content += f"- **Bibliotecas:** {', '.join(tecnologias['bibliotecas'])}\n"
    if tecnologias.get('cms'):
        md_content += f"- **CMS:** {tecnologias['cms']}\n"
    
    md_content += f"""
### Segurança HTTP
- **Score de Segurança:** {detalhes['seguranca'].get('score_headers', {}).get('percentual', 0)}%
- **WAFs Detectados:** {', '.join(detalhes['seguranca'].get('wafs_detectados', [])) or 'Nenhum'}

## Vulnerabilidades Detalhadas
"""
    
    for vuln in detalhes['vulnerabilidades_detalhadas']:
        md_content += f"""
### {vuln['id']} - {vuln['tipo'].upper()}
- **Severidade:** {vuln['severidade']}
- **Localização:** {vuln['localizacao']}
- **Payload:** `{vuln['payload']}`
- **Evidência:** {vuln['evidencia']}
- **Recomendação:** {vuln['recomendacao']}
"""
    
    md_content += f"""
---
*Relatório gerado pelo AEGIS Bug Hunter em {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}*
"""
    
    return md_content

def executar(target_url):
    """Executa geração completa do relatório"""
    print(f"[report_gen] 📊 Gerando relatório técnico para: {target_url}")
    
    try:
        site_name = target_url.replace("https://", "").replace("http://", "").replace("/", "_")
        output_dir = f"output/{site_name}"
        
        # Carrega dados dos módulos
        dados = carregar_dados_modulos(site_name)
        
        # Gera relatório JSON
        relatorio = gerar_relatorio_json(dados, target_url)
        
        # Salva relatório JSON
        arquivo_json = f"{output_dir}/relatorio_final.json"
        with open(arquivo_json, "w", encoding="utf-8") as f:
            json.dump(relatorio, f, indent=4, ensure_ascii=False)
        
        # Gera e salva relatório Markdown
        relatorio_md = gerar_relatorio_markdown(relatorio)
        arquivo_md = f"{output_dir}/relatorio_final.md"
        with open(arquivo_md, "w", encoding="utf-8") as f:
            f.write(relatorio_md)
        
        # Estatísticas do relatório
        resumo = relatorio["resumo_executivo"]
        
        print(f"[report_gen] ✅ Relatório gerado com sucesso")
        print(f"[report_gen] 🎯 Nível de risco: {resumo['nivel_risco']}")
        print(f"[report_gen] 🚨 Vulnerabilidades encontradas: {resumo['total_vulnerabilidades']}")
        print(f"[report_gen] 📄 Relatório JSON: {arquivo_json}")
        print(f"[report_gen] 📝 Relatório Markdown: {arquivo_md}")
        
        return relatorio
        
    except Exception as e:
        print(f"[report_gen] ❌ Erro ao gerar relatório: {str(e)}")
        return {"erro": str(e)}

