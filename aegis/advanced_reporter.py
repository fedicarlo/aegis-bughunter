"""
AEGIS Bug Hunter - Advanced Reporter
Sistema avançado de geração de relatórios em múltiplos formatos
"""

import os
import json
from datetime import datetime
from urllib.parse import urlparse

class AdvancedReporter:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.report_data = {}
    
    def load_all_data(self, target_url):
        """Carrega todos os dados dos módulos"""
        site_name = target_url.replace('https://', '').replace('http://', '').replace('/', '_')
        
        data_files = {
            "pre_recon": "pre_recon.json",
            "headers_analysis": "headers_analysis.json",
            "parser": "parser.json",
            "injects": "injects.json",
            "fuzzer_results": "fuzzer_results.json",
            "defense_analysis": "defense_analysis.json",
            "memory_analysis": "memory_analysis.json",
            "ai_analysis": "ai_analysis.json",
            "relatorio_final": "relatorio_final.json"
        }
        
        loaded_data = {"target_url": target_url}
        
        for module_name, filename in data_files.items():
            file_path = f"{self.output_dir}/{filename}"
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        loaded_data[module_name] = json.load(f)
                except Exception as e:
                    loaded_data[module_name] = {"erro": f"Erro ao carregar {filename}: {str(e)}"}
            else:
                loaded_data[module_name] = {"erro": f"Arquivo {filename} não encontrado"}
        
        self.report_data = loaded_data
        return loaded_data
    
    def generate_html_report(self):
        """Gera relatório em formato HTML"""
        html_content = self._create_html_template()
        
        # Substitui placeholders com dados reais
        html_content = html_content.replace("{{TARGET_URL}}", self.report_data.get("target_url", "N/A"))
        html_content = html_content.replace("{{GENERATION_DATE}}", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
        
        # Adiciona resumo executivo
        executive_summary = self._generate_executive_summary_html()
        html_content = html_content.replace("{{EXECUTIVE_SUMMARY}}", executive_summary)
        
        # Adiciona detalhes técnicos
        technical_details = self._generate_technical_details_html()
        html_content = html_content.replace("{{TECHNICAL_DETAILS}}", technical_details)
        
        # Adiciona vulnerabilidades
        vulnerabilities_section = self._generate_vulnerabilities_html()
        html_content = html_content.replace("{{VULNERABILITIES}}", vulnerabilities_section)
        
        # Salva arquivo HTML
        html_file = f"{self.output_dir}/relatorio_completo.html"
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return html_file
    
    def generate_pdf_report(self):
        """Gera relatório em formato PDF"""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            
            pdf_file = f"{self.output_dir}/relatorio_completo.pdf"
            doc = SimpleDocTemplate(pdf_file, pagesize=A4)
            
            # Estilos
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                textColor=colors.darkblue
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                spaceAfter=12,
                textColor=colors.darkred
            )
            
            # Conteúdo do PDF
            story = []
            
            # Título
            story.append(Paragraph("AEGIS Bug Hunter - Relatório de Segurança", title_style))
            story.append(Spacer(1, 12))
            
            # Informações básicas
            story.append(Paragraph("Informações Gerais", heading_style))
            info_data = [
                ["Alvo:", self.report_data.get("target_url", "N/A")],
                ["Data do Scan:", datetime.now().strftime("%d/%m/%Y %H:%M:%S")],
                ["Versão AEGIS:", "1.0.0"]
            ]
            info_table = Table(info_data, colWidths=[2*inch, 4*inch])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(info_table)
            story.append(Spacer(1, 20))
            
            # Resumo executivo
            story.append(Paragraph("Resumo Executivo", heading_style))
            executive_summary = self._generate_executive_summary_text()
            story.append(Paragraph(executive_summary, styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Vulnerabilidades encontradas
            story.append(Paragraph("Vulnerabilidades Encontradas", heading_style))
            vulns_table = self._create_vulnerabilities_table()
            if vulns_table:
                story.append(vulns_table)
            else:
                story.append(Paragraph("Nenhuma vulnerabilidade detectada.", styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Recomendações
            story.append(Paragraph("Recomendações", heading_style))
            recommendations = self._generate_recommendations_text()
            story.append(Paragraph(recommendations, styles['Normal']))
            
            # Gera PDF
            doc.build(story)
            return pdf_file
            
        except ImportError:
            print("[advanced_reporter] ⚠️ ReportLab não disponível, pulando geração de PDF")
            return None
        except Exception as e:
            print(f"[advanced_reporter] ❌ Erro ao gerar PDF: {str(e)}")
            return None
    
    def _create_html_template(self):
        """Cria template HTML base"""
        return """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AEGIS Bug Hunter - Relatório de Segurança</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #2c3e50;
            margin: 0;
            font-size: 2.5em;
        }
        .header .subtitle {
            color: #7f8c8d;
            font-size: 1.2em;
            margin-top: 10px;
        }
        .section {
            margin-bottom: 30px;
        }
        .section h2 {
            color: #e74c3c;
            border-left: 4px solid #e74c3c;
            padding-left: 15px;
            margin-bottom: 20px;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .info-card {
            background-color: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }
        .info-card h3 {
            margin-top: 0;
            color: #2c3e50;
        }
        .vulnerability {
            background-color: #fff5f5;
            border: 1px solid #fed7d7;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
        }
        .vulnerability.critical {
            border-left: 4px solid #e53e3e;
        }
        .vulnerability.high {
            border-left: 4px solid #dd6b20;
        }
        .vulnerability.medium {
            border-left: 4px solid #d69e2e;
        }
        .vulnerability.low {
            border-left: 4px solid #38a169;
        }
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-critical {
            background-color: #e53e3e;
            color: white;
        }
        .severity-high {
            background-color: #dd6b20;
            color: white;
        }
        .severity-medium {
            background-color: #d69e2e;
            color: white;
        }
        .severity-low {
            background-color: #38a169;
            color: white;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #bdc3c7;
            color: #7f8c8d;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        .code {
            background-color: #f8f9fa;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AEGIS Bug Hunter</h1>
            <div class="subtitle">Relatório de Segurança Automatizado</div>
            <div class="subtitle">Alvo: {{TARGET_URL}}</div>
            <div class="subtitle">Gerado em: {{GENERATION_DATE}}</div>
        </div>
        
        <div class="section">
            <h2>📊 Resumo Executivo</h2>
            {{EXECUTIVE_SUMMARY}}
        </div>
        
        <div class="section">
            <h2>🔧 Detalhes Técnicos</h2>
            {{TECHNICAL_DETAILS}}
        </div>
        
        <div class="section">
            <h2>🚨 Vulnerabilidades Encontradas</h2>
            {{VULNERABILITIES}}
        </div>
        
        <div class="footer">
            <p>Relatório gerado pelo AEGIS Bug Hunter v1.0.0</p>
            <p>Sistema Autônomo de Bug Bounty com IA</p>
        </div>
    </div>
</body>
</html>
"""
    
    def _generate_executive_summary_html(self):
        """Gera resumo executivo em HTML"""
        relatorio_final = self.report_data.get("relatorio_final", {})
        resumo = relatorio_final.get("resumo_executivo", {})
        
        if not resumo:
            return "<p>Dados do resumo executivo não disponíveis.</p>"
        
        html = f"""
        <div class="info-grid">
            <div class="info-card">
                <h3>🎯 Status Geral</h3>
                <p><strong>Nível de Risco:</strong> {resumo.get('nivel_risco', 'N/A')}</p>
                <p><strong>Total de Vulnerabilidades:</strong> {resumo.get('total_vulnerabilidades', 0)}</p>
            </div>
            <div class="info-card">
                <h3>📈 Distribuição por Severidade</h3>
                <p><strong>Críticas:</strong> {resumo.get('vulnerabilidades_criticas', 0)}</p>
                <p><strong>Altas:</strong> {resumo.get('vulnerabilidades_altas', 0)}</p>
                <p><strong>Médias:</strong> {resumo.get('vulnerabilidades_medias', 0)}</p>
                <p><strong>Baixas:</strong> {resumo.get('vulnerabilidades_baixas', 0)}</p>
            </div>
        </div>
        """
        
        # Adiciona recomendações prioritárias
        recomendacoes = resumo.get('recomendacoes_prioritarias', [])
        if recomendacoes:
            html += "<h3>🎯 Recomendações Prioritárias</h3><ul>"
            for rec in recomendacoes:
                html += f"<li>{rec}</li>"
            html += "</ul>"
        
        return html
    
    def _generate_technical_details_html(self):
        """Gera detalhes técnicos em HTML"""
        pre_recon = self.report_data.get("pre_recon", {})
        headers_analysis = self.report_data.get("headers_analysis", {})
        parser_data = self.report_data.get("parser", {})
        
        html = '<div class="info-grid">'
        
        # Informações de infraestrutura
        if "resumo" in pre_recon:
            resumo = pre_recon["resumo"]
            html += f"""
            <div class="info-card">
                <h3>🌐 Infraestrutura</h3>
                <p><strong>Servidor:</strong> {resumo.get('servidor', 'N/A')}</p>
                <p><strong>SSL/TLS:</strong> {'✅ Habilitado' if resumo.get('tem_ssl') else '❌ Não habilitado'}</p>
                <p><strong>WAF:</strong> {'✅ Detectado' if resumo.get('tem_waf') else '❌ Não detectado'}</p>
                <p><strong>Portas Abertas:</strong> {resumo.get('portas_encontradas', 0)}</p>
            </div>
            """
        
        # Score de segurança
        if "score_seguranca" in headers_analysis:
            score = headers_analysis["score_seguranca"]
            html += f"""
            <div class="info-card">
                <h3>🔒 Segurança HTTP</h3>
                <p><strong>Score:</strong> {score.get('percentual', 0)}% ({score.get('nivel', 'N/A')})</p>
                <p><strong>Headers de Segurança:</strong> {score.get('score', 0)}/{score.get('max_score', 6)}</p>
            </div>
            """
        
        # Análise de conteúdo
        if "resumo" in parser_data:
            resumo_parser = parser_data["resumo"]
            html += f"""
            <div class="info-card">
                <h3>📄 Análise de Conteúdo</h3>
                <p><strong>Formulários:</strong> {len(parser_data.get('formularios', []))}</p>
                <p><strong>Links:</strong> {parser_data.get('links', {}).get('total', 0)}</p>
                <p><strong>Scripts:</strong> {len(parser_data.get('scripts', []))}</p>
                <p><strong>Densidade de Texto:</strong> {resumo_parser.get('densidade_texto', 0)}%</p>
            </div>
            """
        
        html += '</div>'
        return html
    
    def _generate_vulnerabilities_html(self):
        """Gera seção de vulnerabilidades em HTML"""
        relatorio_final = self.report_data.get("relatorio_final", {})
        detalhes = relatorio_final.get("detalhes_tecnicos", {})
        vulnerabilidades = detalhes.get("vulnerabilidades_detalhadas", [])
        
        if not vulnerabilidades:
            return "<p>✅ Nenhuma vulnerabilidade foi detectada durante a análise.</p>"
        
        html = ""
        for vuln in vulnerabilidades:
            severidade = vuln.get('severidade', 'LOW').lower()
            html += f"""
            <div class="vulnerability {severidade}">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <h3 style="margin: 0;">{vuln.get('id', 'N/A')} - {vuln.get('tipo', 'N/A').upper()}</h3>
                    <span class="severity-badge severity-{severidade}">{vuln.get('severidade', 'LOW')}</span>
                </div>
                <p><strong>Localização:</strong> <span class="code">{vuln.get('localizacao', 'N/A')}</span></p>
                <p><strong>Payload:</strong> <span class="code">{vuln.get('payload', 'N/A')}</span></p>
                <p><strong>Evidência:</strong> {vuln.get('evidencia', 'N/A')}</p>
                <p><strong>Recomendação:</strong> {vuln.get('recomendacao', 'N/A')}</p>
            </div>
            """
        
        return html
    
    def _generate_executive_summary_text(self):
        """Gera resumo executivo em texto simples"""
        relatorio_final = self.report_data.get("relatorio_final", {})
        resumo = relatorio_final.get("resumo_executivo", {})
        
        if not resumo:
            return "Dados do resumo executivo não disponíveis."
        
        text = f"""
        Durante a análise automatizada do alvo {resumo.get('alvo', 'N/A')}, o sistema AEGIS identificou um total de {resumo.get('total_vulnerabilidades', 0)} vulnerabilidades.
        
        O nível de risco geral foi classificado como {resumo.get('nivel_risco', 'N/A')}, baseado na distribuição de severidades encontradas:
        - Vulnerabilidades Críticas: {resumo.get('vulnerabilidades_criticas', 0)}
        - Vulnerabilidades Altas: {resumo.get('vulnerabilidades_altas', 0)}
        - Vulnerabilidades Médias: {resumo.get('vulnerabilidades_medias', 0)}
        - Vulnerabilidades Baixas: {resumo.get('vulnerabilidades_baixas', 0)}
        
        As principais recomendações incluem a correção imediata das vulnerabilidades críticas e implementação de medidas de segurança adicionais.
        """
        
        return text.strip()
    
    def _create_vulnerabilities_table(self):
        """Cria tabela de vulnerabilidades para PDF"""
        try:
            from reportlab.platypus import Table, TableStyle
            from reportlab.lib import colors
            
            relatorio_final = self.report_data.get("relatorio_final", {})
            detalhes = relatorio_final.get("detalhes_tecnicos", {})
            vulnerabilidades = detalhes.get("vulnerabilidades_detalhadas", [])
            
            if not vulnerabilidades:
                return None
            
            # Cabeçalho da tabela
            data = [["ID", "Tipo", "Severidade", "Localização"]]
            
            # Adiciona vulnerabilidades
            for vuln in vulnerabilidades[:10]:  # Limita para não ficar muito grande
                data.append([
                    vuln.get('id', 'N/A'),
                    vuln.get('tipo', 'N/A'),
                    vuln.get('severidade', 'LOW'),
                    vuln.get('localizacao', 'N/A')[:30] + "..." if len(vuln.get('localizacao', '')) > 30 else vuln.get('localizacao', 'N/A')
                ])
            
            table = Table(data, colWidths=[1*inch, 1.5*inch, 1*inch, 2.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            return table
            
        except ImportError:
            return None
    
    def _generate_recommendations_text(self):
        """Gera texto de recomendações"""
        relatorio_final = self.report_data.get("relatorio_final", {})
        resumo = relatorio_final.get("resumo_executivo", {})
        recomendacoes = resumo.get('recomendacoes_prioritarias', [])
        
        if not recomendacoes:
            return "Nenhuma recomendação específica identificada. Continue monitorando a segurança do sistema."
        
        text = "Com base na análise realizada, recomendamos as seguintes ações prioritárias:\n\n"
        for i, rec in enumerate(recomendacoes, 1):
            text += f"{i}. {rec}\n"
        
        text += "\nImplemente essas medidas o mais rápido possível para melhorar a postura de segurança do sistema."
        
        return text

def executar(target_url):
    """Executa geração avançada de relatórios"""
    print(f"[advanced_reporter] 📊 Gerando relatórios avançados para: {target_url}")
    
    try:
        site_name = target_url.replace('https://', '').replace('http://', '').replace('/', '_')
        output_dir = f"output/{site_name}"
        
        reporter = AdvancedReporter(output_dir)
        reporter.load_all_data(target_url)
        
        resultados = {
            "target_url": target_url,
            "timestamp": datetime.now().isoformat(),
            "relatorios_gerados": [],
            "erros": []
        }
        
        # Gera relatório HTML
        try:
            html_file = reporter.generate_html_report()
            if html_file:
                resultados["relatorios_gerados"].append(f"HTML: {os.path.basename(html_file)}")
                print(f"[advanced_reporter] ✅ Relatório HTML gerado: {html_file}")
        except Exception as e:
            resultados["erros"].append(f"Erro ao gerar HTML: {str(e)}")
        
        # Gera relatório PDF
        try:
            pdf_file = reporter.generate_pdf_report()
            if pdf_file:
                resultados["relatorios_gerados"].append(f"PDF: {os.path.basename(pdf_file)}")
                print(f"[advanced_reporter] ✅ Relatório PDF gerado: {pdf_file}")
        except Exception as e:
            resultados["erros"].append(f"Erro ao gerar PDF: {str(e)}")
        
        # Salva resultado
        arquivo_saida = f"{output_dir}/advanced_reports.json"
        with open(arquivo_saida, "w", encoding="utf-8") as f:
            json.dump(resultados, f, indent=4, ensure_ascii=False)
        
        print(f"[advanced_reporter] ✅ Relatórios avançados gerados")
        print(f"[advanced_reporter] 📄 Formatos: {len(resultados['relatorios_gerados'])}")
        print(f"[advanced_reporter] 💾 Log salvo em: {arquivo_saida}")
        
        return resultados
        
    except Exception as e:
        print(f"[advanced_reporter] ❌ Erro na geração de relatórios: {str(e)}")
        return {"erro": str(e)}

