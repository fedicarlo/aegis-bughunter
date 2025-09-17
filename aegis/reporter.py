"""
AEGIS Bug Hunter - Reporter
Módulo responsável por envio e exportação de relatórios
"""

import os
import json
import smtplib
import zipfile
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

def criar_pacote_relatorio(target_url, output_dir):
    """Cria pacote ZIP com todos os arquivos do relatório"""
    site_name = target_url.replace("https://", "").replace("http://", "").replace("/", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_zip = f"aegis_report_{site_name}_{timestamp}.zip"
    caminho_zip = f"{output_dir}/{nome_zip}"
    
    try:
        with zipfile.ZipFile(caminho_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Adiciona todos os arquivos JSON do output
            for arquivo in os.listdir(output_dir):
                if arquivo.endswith(('.json', '.md', '.txt')):
                    caminho_arquivo = f"{output_dir}/{arquivo}"
                    zipf.write(caminho_arquivo, arquivo)
            
            # Adiciona logs se existirem
            if os.path.exists("logs"):
                for arquivo in os.listdir("logs"):
                    if arquivo.endswith('.log'):
                        caminho_log = f"logs/{arquivo}"
                        zipf.write(caminho_log, f"logs/{arquivo}")
        
        print(f"[reporter] 📦 Pacote criado: {nome_zip}")
        return caminho_zip
        
    except Exception as e:
        print(f"[reporter] ❌ Erro ao criar pacote: {str(e)}")
        return None

def gerar_resumo_email(relatorio_data):
    """Gera resumo para envio por email"""
    if "resumo_executivo" not in relatorio_data:
        return "Relatório de segurança gerado pelo AEGIS Bug Hunter"
    
    resumo = relatorio_data["resumo_executivo"]
    
    email_content = f"""
Relatório de Segurança - AEGIS Bug Hunter

ALVO: {resumo.get('alvo', 'N/A')}
DATA: {resumo.get('data_analise', 'N/A')}
NÍVEL DE RISCO: {resumo.get('nivel_risco', 'N/A')}

VULNERABILIDADES ENCONTRADAS:
- Total: {resumo.get('total_vulnerabilidades', 0)}
- Críticas: {resumo.get('vulnerabilidades_criticas', 0)}
- Altas: {resumo.get('vulnerabilidades_altas', 0)}
- Médias: {resumo.get('vulnerabilidades_medias', 0)}
- Baixas: {resumo.get('vulnerabilidades_baixas', 0)}

RECOMENDAÇÕES PRIORITÁRIAS:
"""
    
    for rec in resumo.get('recomendacoes_prioritarias', []):
        email_content += f"- {rec}\n"
    
    email_content += f"""
Este é um relatório automatizado gerado pelo AEGIS Bug Hunter.
Verifique os arquivos anexos para detalhes completos.

---
AEGIS Bug Hunter - Sistema Autônomo de Bug Bounty
Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
"""
    
    return email_content

def enviar_email_relatorio(destinatario, relatorio_data, caminho_zip=None, config_email=None):
    """Envia relatório por email"""
    if not config_email:
        print(f"[reporter] ⚠️ Configuração de email não fornecida")
        return False
    
    try:
        # Configura email
        msg = MIMEMultipart()
        msg['From'] = config_email.get('remetente', 'aegis@security.local')
        msg['To'] = destinatario
        msg['Subject'] = f"Relatório AEGIS - {relatorio_data.get('metadata', {}).get('target', 'Alvo')}"
        
        # Corpo do email
        corpo = gerar_resumo_email(relatorio_data)
        msg.attach(MIMEText(corpo, 'plain', 'utf-8'))
        
        # Anexa ZIP se disponível
        if caminho_zip and os.path.exists(caminho_zip):
            with open(caminho_zip, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename= {os.path.basename(caminho_zip)}'
                )
                msg.attach(part)
        
        # Envia email
        server = smtplib.SMTP(config_email.get('smtp_server', 'localhost'), config_email.get('smtp_port', 587))
        if config_email.get('usar_tls', True):
            server.starttls()
        if config_email.get('usuario') and config_email.get('senha'):
            server.login(config_email['usuario'], config_email['senha'])
        
        server.sendmail(msg['From'], msg['To'], msg.as_string())
        server.quit()
        
        print(f"[reporter] ✅ Email enviado para: {destinatario}")
        return True
        
    except Exception as e:
        print(f"[reporter] ❌ Erro ao enviar email: {str(e)}")
        return False

def enviar_webhook(url_webhook, relatorio_data):
    """Envia relatório via webhook"""
    import requests
    
    try:
        # Prepara payload
        payload = {
            "timestamp": datetime.now().isoformat(),
            "source": "AEGIS Bug Hunter",
            "target": relatorio_data.get('metadata', {}).get('target', 'N/A'),
            "risk_level": relatorio_data.get('resumo_executivo', {}).get('nivel_risco', 'N/A'),
            "vulnerabilities": relatorio_data.get('resumo_executivo', {}).get('total_vulnerabilidades', 0),
            "summary": gerar_resumo_email(relatorio_data)
        }
        
        # Envia webhook
        response = requests.post(url_webhook, json=payload, timeout=10)
        response.raise_for_status()
        
        print(f"[reporter] ✅ Webhook enviado: {url_webhook}")
        return True
        
    except Exception as e:
        print(f"[reporter] ❌ Erro ao enviar webhook: {str(e)}")
        return False

def salvar_relatorio_compartilhado(relatorio_data, output_dir):
    """Salva relatório em diretório compartilhado"""
    try:
        # Cria diretório compartilhado se não existir
        shared_dir = "shared_reports"
        os.makedirs(shared_dir, exist_ok=True)
        
        # Nome do arquivo baseado no alvo e timestamp
        target = relatorio_data.get('metadata', {}).get('target', 'unknown')
        site_name = target.replace("https://", "").replace("http://", "").replace("/", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        arquivo_shared = f"{shared_dir}/aegis_report_{site_name}_{timestamp}.json"
        
        with open(arquivo_shared, 'w', encoding='utf-8') as f:
            json.dump(relatorio_data, f, indent=4, ensure_ascii=False)
        
        print(f"[reporter] 💾 Relatório salvo em: {arquivo_shared}")
        return arquivo_shared
        
    except Exception as e:
        print(f"[reporter] ❌ Erro ao salvar relatório compartilhado: {str(e)}")
        return None

def gerar_relatorio_csv(relatorio_data, output_dir):
    """Gera versão CSV das vulnerabilidades para análise"""
    try:
        import csv
        
        vulnerabilidades = relatorio_data.get('detalhes_tecnicos', {}).get('vulnerabilidades_detalhadas', [])
        
        if not vulnerabilidades:
            print(f"[reporter] ⚠️ Nenhuma vulnerabilidade para exportar em CSV")
            return None
        
        arquivo_csv = f"{output_dir}/vulnerabilidades.csv"
        
        with open(arquivo_csv, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['id', 'tipo', 'severidade', 'localizacao', 'payload', 'evidencia', 'recomendacao']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for vuln in vulnerabilidades:
                writer.writerow(vuln)
        
        print(f"[reporter] 📊 CSV gerado: {arquivo_csv}")
        return arquivo_csv
        
    except Exception as e:
        print(f"[reporter] ❌ Erro ao gerar CSV: {str(e)}")
        return None

def carregar_configuracao_reporter():
    """Carrega configuração do reporter se existir"""
    config_file = "config/reporter_config.json"
    
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            pass
    
    # Configuração padrão
    return {
        "email": {
            "habilitado": False,
            "destinatarios": [],
            "smtp_server": "localhost",
            "smtp_port": 587,
            "usar_tls": True,
            "usuario": "",
            "senha": "",
            "remetente": "aegis@security.local"
        },
        "webhook": {
            "habilitado": False,
            "urls": []
        },
        "compartilhado": {
            "habilitado": True,
            "diretorio": "shared_reports"
        },
        "formatos": {
            "csv": True,
            "zip": True
        }
    }

def executar(target_url):
    """Executa envio/exportação do relatório final"""
    print(f"[reporter] 📤 Enviando relatório final sobre: {target_url}")
    
    try:
        site_name = target_url.replace("https://", "").replace("http://", "").replace("/", "_")
        output_dir = f"output/{site_name}"
        
        # Carrega relatório final
        arquivo_relatorio = f"{output_dir}/relatorio_final.json"
        if not os.path.exists(arquivo_relatorio):
            print(f"[reporter] ❌ Relatório final não encontrado: {arquivo_relatorio}")
            return {"erro": "Relatório final não encontrado"}
        
        with open(arquivo_relatorio, 'r', encoding='utf-8') as f:
            relatorio_data = json.load(f)
        
        # Carrega configuração
        config = carregar_configuracao_reporter()
        
        resultados = {
            "target_url": target_url,
            "timestamp": datetime.now().isoformat(),
            "acoes_executadas": [],
            "erros": []
        }
        
        # Cria pacote ZIP
        if config.get("formatos", {}).get("zip", True):
            caminho_zip = criar_pacote_relatorio(target_url, output_dir)
            if caminho_zip:
                resultados["acoes_executadas"].append(f"Pacote ZIP criado: {os.path.basename(caminho_zip)}")
        else:
            caminho_zip = None
        
        # Gera CSV
        if config.get("formatos", {}).get("csv", True):
            arquivo_csv = gerar_relatorio_csv(relatorio_data, output_dir)
            if arquivo_csv:
                resultados["acoes_executadas"].append(f"CSV gerado: {os.path.basename(arquivo_csv)}")
        
        # Salva em diretório compartilhado
        if config.get("compartilhado", {}).get("habilitado", True):
            arquivo_shared = salvar_relatorio_compartilhado(relatorio_data, output_dir)
            if arquivo_shared:
                resultados["acoes_executadas"].append(f"Relatório compartilhado salvo: {os.path.basename(arquivo_shared)}")
        
        # Envia emails
        if config.get("email", {}).get("habilitado", False):
            destinatarios = config["email"].get("destinatarios", [])
            for destinatario in destinatarios:
                sucesso = enviar_email_relatorio(destinatario, relatorio_data, caminho_zip, config["email"])
                if sucesso:
                    resultados["acoes_executadas"].append(f"Email enviado para: {destinatario}")
                else:
                    resultados["erros"].append(f"Falha ao enviar email para: {destinatario}")
        
        # Envia webhooks
        if config.get("webhook", {}).get("habilitado", False):
            urls = config["webhook"].get("urls", [])
            for url in urls:
                sucesso = enviar_webhook(url, relatorio_data)
                if sucesso:
                    resultados["acoes_executadas"].append(f"Webhook enviado: {url}")
                else:
                    resultados["erros"].append(f"Falha ao enviar webhook: {url}")
        
        # Salva log de ações
        log_file = f"{output_dir}/reporter_log.json"
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(resultados, f, indent=4, ensure_ascii=False)
        
        print(f"[reporter] ✅ Relatório processado")
        print(f"[reporter] 📋 Ações executadas: {len(resultados['acoes_executadas'])}")
        if resultados["erros"]:
            print(f"[reporter] ⚠️ Erros encontrados: {len(resultados['erros'])}")
        
        return resultados
        
    except Exception as e:
        print(f"[reporter] ❌ Erro no processamento: {str(e)}")
        return {"erro": str(e)}

