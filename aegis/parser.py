"""
AEGIS Bug Hunter - HTML Parser
Módulo responsável pela análise e parsing de conteúdo HTML
"""

import os
import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime
import re

def extrair_formularios(soup, base_url):
    """Extrai todos os formulários da página"""
    formularios = []
    
    for form in soup.find_all('form'):
        form_info = {
            "action": form.get('action', ''),
            "method": form.get('method', 'GET').upper(),
            "enctype": form.get('enctype', 'application/x-www-form-urlencoded'),
            "campos": [],
            "url_completa": None
        }
        
        # Resolve URL completa do action
        if form_info["action"]:
            form_info["url_completa"] = urljoin(base_url, form_info["action"])
        else:
            form_info["url_completa"] = base_url
        
        # Extrai campos do formulário
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            campo = {
                "tag": input_tag.name,
                "type": input_tag.get('type', 'text'),
                "name": input_tag.get('name', ''),
                "id": input_tag.get('id', ''),
                "value": input_tag.get('value', ''),
                "placeholder": input_tag.get('placeholder', ''),
                "required": input_tag.has_attr('required'),
                "maxlength": input_tag.get('maxlength', ''),
                "pattern": input_tag.get('pattern', '')
            }
            
            # Para selects, extrai opções
            if input_tag.name == 'select':
                campo["opcoes"] = []
                for option in input_tag.find_all('option'):
                    campo["opcoes"].append({
                        "value": option.get('value', ''),
                        "text": option.get_text(strip=True)
                    })
            
            form_info["campos"].append(campo)
        
        formularios.append(form_info)
    
    return formularios

def extrair_links(soup, base_url):
    """Extrai todos os links da página"""
    links = []
    
    for link in soup.find_all('a', href=True):
        href = link['href']
        url_completa = urljoin(base_url, href)
        
        link_info = {
            "href": href,
            "url_completa": url_completa,
            "texto": link.get_text(strip=True),
            "title": link.get('title', ''),
            "target": link.get('target', ''),
            "rel": link.get('rel', []),
            "tipo": "interno" if urlparse(url_completa).netloc == urlparse(base_url).netloc else "externo"
        }
        
        links.append(link_info)
    
    return links

def extrair_scripts(soup):
    """Extrai informações sobre scripts"""
    scripts = []
    
    for script in soup.find_all('script'):
        script_info = {
            "src": script.get('src', ''),
            "type": script.get('type', 'text/javascript'),
            "async": script.has_attr('async'),
            "defer": script.has_attr('defer'),
            "inline": script.get('src') is None,
            "conteudo_tamanho": len(script.get_text()) if script.get_text() else 0
        }
        
        # Analisa conteúdo inline para possíveis vulnerabilidades
        if script_info["inline"] and script.get_text():
            conteudo = script.get_text()
            script_info["possiveis_vulnerabilidades"] = []
            
            # Verifica padrões suspeitos
            if "eval(" in conteudo:
                script_info["possiveis_vulnerabilidades"].append("uso_de_eval")
            if "innerHTML" in conteudo:
                script_info["possiveis_vulnerabilidades"].append("uso_de_innerHTML")
            if "document.write" in conteudo:
                script_info["possiveis_vulnerabilidades"].append("uso_de_document_write")
            if re.search(r'\.location\s*=', conteudo):
                script_info["possiveis_vulnerabilidades"].append("redirecionamento_dinamico")
        
        scripts.append(script_info)
    
    return scripts

def extrair_metas(soup):
    """Extrai meta tags importantes"""
    metas = {}
    
    for meta in soup.find_all('meta'):
        name = meta.get('name', '')
        property_attr = meta.get('property', '')
        content = meta.get('content', '')
        
        if name:
            metas[name] = content
        elif property_attr:
            metas[property_attr] = content
        elif meta.get('charset'):
            metas['charset'] = meta.get('charset')
        elif meta.get('http-equiv'):
            metas[f"http-equiv-{meta.get('http-equiv')}"] = content
    
    return metas

def extrair_comentarios(soup):
    """Extrai comentários HTML que podem conter informações sensíveis"""
    from bs4 import Comment
    
    comentarios = []
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    
    for comment in comments:
        comment_text = comment.strip()
        if comment_text:
            comentario_info = {
                "conteudo": comment_text,
                "tamanho": len(comment_text),
                "possiveis_problemas": []
            }
            
            # Verifica por informações sensíveis
            comment_lower = comment_text.lower()
            if any(palavra in comment_lower for palavra in ['password', 'senha', 'key', 'token', 'secret']):
                comentario_info["possiveis_problemas"].append("informacao_sensivel")
            if any(palavra in comment_lower for palavra in ['todo', 'fixme', 'hack', 'bug']):
                comentario_info["possiveis_problemas"].append("nota_desenvolvimento")
            if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', comment_text):
                comentario_info["possiveis_problemas"].append("endereco_ip")
            
            comentarios.append(comentario_info)
    
    return comentarios

def analisar_tecnologias_frontend(soup, headers=None):
    """Analisa tecnologias frontend baseado no HTML"""
    tecnologias = {
        "frameworks": [],
        "bibliotecas": [],
        "cms": None,
        "analytics": [],
        "cdn": []
    }
    
    # Analisa scripts para detectar frameworks/bibliotecas
    for script in soup.find_all('script', src=True):
        src = script['src'].lower()
        
        if 'jquery' in src:
            tecnologias["bibliotecas"].append("jQuery")
        elif 'react' in src:
            tecnologias["frameworks"].append("React")
        elif 'angular' in src:
            tecnologias["frameworks"].append("Angular")
        elif 'vue' in src:
            tecnologias["frameworks"].append("Vue.js")
        elif 'bootstrap' in src:
            tecnologias["frameworks"].append("Bootstrap")
        elif 'google-analytics' in src or 'gtag' in src:
            tecnologias["analytics"].append("Google Analytics")
        elif 'googleapis.com' in src:
            tecnologias["cdn"].append("Google APIs")
        elif 'cdnjs.cloudflare.com' in src:
            tecnologias["cdn"].append("Cloudflare CDN")
    
    # Detecta CMS por meta tags e padrões
    generator = soup.find('meta', attrs={'name': 'generator'})
    if generator:
        content = generator.get('content', '').lower()
        if 'wordpress' in content:
            tecnologias["cms"] = "WordPress"
        elif 'drupal' in content:
            tecnologias["cms"] = "Drupal"
        elif 'joomla' in content:
            tecnologias["cms"] = "Joomla"
    
    # Remove duplicatas
    for key in ['frameworks', 'bibliotecas', 'analytics', 'cdn']:
        tecnologias[key] = list(set(tecnologias[key]))
    
    return tecnologias

def calcular_metricas_pagina(soup, response_text):
    """Calcula métricas da página"""
    metricas = {
        "tamanho_html": len(response_text),
        "total_elementos": len(soup.find_all()),
        "total_links": len(soup.find_all('a')),
        "total_imagens": len(soup.find_all('img')),
        "total_formularios": len(soup.find_all('form')),
        "total_scripts": len(soup.find_all('script')),
        "total_estilos": len(soup.find_all(['style', 'link'], rel='stylesheet')),
        "densidade_texto": 0
    }
    
    # Calcula densidade de texto
    texto_total = soup.get_text()
    if metricas["tamanho_html"] > 0:
        metricas["densidade_texto"] = round((len(texto_total) / metricas["tamanho_html"]) * 100, 2)
    
    return metricas

def executar(target_url):
    """Executa parsing completo da página"""
    print(f"[parser] 🔍 Fazendo parse da página: {target_url}")
    
    try:
        # Faz requisição
        response = requests.get(target_url, timeout=10)
        response.raise_for_status()
        
        # Cria objeto BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extrai informações
        title = soup.title.string.strip() if soup.title else "Sem título"
        metas = extrair_metas(soup)
        formularios = extrair_formularios(soup, target_url)
        links = extrair_links(soup, target_url)
        scripts = extrair_scripts(soup)
        comentarios = extrair_comentarios(soup)
        tecnologias = analisar_tecnologias_frontend(soup)
        metricas = calcular_metricas_pagina(soup, response.text)
        
        # Compila resultado
        resultado = {
            "target_url": target_url,
            "timestamp": datetime.now().isoformat(),
            "title": title,
            "metas": metas,
            "formularios": formularios,
            "links": {
                "total": len(links),
                "internos": len([l for l in links if l["tipo"] == "interno"]),
                "externos": len([l for l in links if l["tipo"] == "externo"]),
                "lista": links[:50]  # Limita para não ficar muito grande
            },
            "scripts": scripts,
            "comentarios": comentarios,
            "tecnologias": tecnologias,
            "metricas": metricas,
            "resumo": {
                "tem_formularios": len(formularios) > 0,
                "formularios_post": len([f for f in formularios if f["method"] == "POST"]),
                "scripts_inline": len([s for s in scripts if s["inline"]]),
                "comentarios_suspeitos": len([c for c in comentarios if c["possiveis_problemas"]]),
                "densidade_texto": metricas["densidade_texto"]
            }
        }
        
        # Salva resultado
        site_name = target_url.replace('https://', '').replace('http://', '').replace('/', '_')
        output_dir = f"output/{site_name}"
        os.makedirs(output_dir, exist_ok=True)
        
        arquivo_saida = f"{output_dir}/parser.json"
        with open(arquivo_saida, "w", encoding="utf-8") as f:
            json.dump(resultado, f, indent=4, ensure_ascii=False)
        
        print(f"[parser] ✅ Parse concluído")
        print(f"[parser] 📄 Título: {title}")
        print(f"[parser] 📝 Formulários encontrados: {len(formularios)}")
        print(f"[parser] 🔗 Links encontrados: {len(links)}")
        print(f"[parser] 📜 Scripts encontrados: {len(scripts)}")
        print(f"[parser] 💾 Resultado salvo em: {arquivo_saida}")
        
        return resultado
        
    except Exception as e:
        print(f"[parser] ❌ Erro ao analisar conteúdo: {str(e)}")
        return {"erro": str(e)}

