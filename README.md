# 🛡️ AEGIS Bug Hunter

**Sistema Autônomo de Bug Bounty com IA Embarcada**  
*"O hacker que nunca dorme"*

---

## 1. Descrição

O AEGIS Bug Hunter é um sistema automatizado e inteligente para descoberta de vulnerabilidades em aplicações web. Desenvolvido com IA embarcada, ele executa análises abrangentes de segurança de forma autônoma, identificando falhas e gerando relatórios detalhados.

---

## 2. Características Principais

### 2.1 IA Embarcada
- Análise de padrões de vulnerabilidades
- Aprendizado contínuo com memória local
- Geração automática de payloads adaptativos
- Correlação de dados e sugestões de próximos passos

### 2.2 Módulos de Análise
- Pre-Recon: fingerprinting e reconhecimento inicial
- Headers Analyzer: análise de segurança em cabeçalhos HTTP
- Parser: análise da estrutura HTML, scripts e formulários
- Inject Finder: verificação de SQLi, XSS, header injection etc.
- Fuzzer Adaptativo: fuzzing evasivo e inteligente
- Defense Detector: detecção de WAF, rate limiting e CAPTCHAs
- Memory System: comparação com vulnerabilidades anteriores
- AI Interpreter: interpretação dos resultados via IA

### 2.3 Sistema de Relatórios
- Geração automática nos formatos: JSON, Markdown, HTML e PDF
- Resumo executivo + seção técnica
- Evidências, payloads, grau de risco e recomendações

### 2.4 Recursos Avançados
- Detecção automática de WAF e sistemas de proteção
- Bypass de rate limit com delay adaptativo
- Rotação de User-Agents e headers
- Modo stealth ativado por padrão
- Arquitetura modular com configuração via JSON

---

## 3. Instalação

### 3.1 Pré-requisitos
- Python 3.8+
- pip3
- Conexão com internet

### 3.2 Instalação das dependências
```bash
cd aegishunter
pip3 install -r requirements.txt
```

### Dependências Opcionais
Para funcionalidades avançadas:
```bash
# Para geração de PDF
pip3 install reportlab

# Para IA com OpenAI
pip3 install openai

# Para análise avançada de imagens
pip3 install pillow
```

## 4. Uso Básico

### Execução Simples
```bash
python3 run.py
```

### 4.2 Execução com Alvo Específico
```bash
echo "https://exemplo.com" | python3 run.py
```

### 4.3 Execução com Configuração Customizada
```bash
# Edite config/aegis_config.json antes da execução
python3 run.py
```

## 5. Configuração Avançada

O sistema utiliza o arquivo `config/aegis_config.json` para configurações avançadas:

### 5.1 Scanning
```json
{
    "scanning": {
        "default_timeout": 10,
        "max_threads": 5,
        "delay_between_requests": {
            "min": 0.5,
            "max": 2.0
        },
        "stealth_mode": true
    }
}
```

### 5.2 Configurações de IA
```json
{
    "ai_interpreter": {
        "enabled": true,
        "use_openai": true,
        "model": "gpt-3.5-turbo",
        "max_tokens": 1000
    }
}
```

### 5.3 Configurações de Relatórios
```json
{
    "reporting": {
        "formats": {
            "json": true,
            "markdown": true,
            "pdf": true,
            "html": true
        }
    }
}
```

## 6 Estrutura do Projeto

```
aegishunter/
├── run.py                      # Arquivo principal de execução
├── requirements.txt            # Dependências Python
├── README.md                   # Documentação
├── config/
│   └── aegis_config.json      # Arquivo de configuração
├── aegis/                     # Módulos principais
│   ├── __init__.py
│   ├── agent_loop.py          # Loop principal do agente
│   ├── pre_recon.py           # Reconhecimento inicial
│   ├── headers_analyzer.py    # Análise de cabeçalhos
│   ├── parser.py              # Parser de conteúdo
│   ├── inject_finder.py       # Detector de injeções
│   ├── fuzzer.py              # Fuzzer adaptativo
│   ├── defense_detector.py    # Detector de defesas
│   ├── memory_system.py       # Sistema de memória
│   ├── ai_interpreter.py      # Interpretador IA
│   ├── config_manager.py      # Gerenciador de configuração
│   ├── advanced_reporter.py   # Sistema de relatórios
│   ├── report_gen.py          # Gerador de relatórios
│   ├── reporter.py            # Reporter básico
│   └── estado_printer.py      # Printer de estado
├── output/                    # Diretório de saída
├── logs/                      # Logs do sistema
└── shared_reports/            # Relatórios compartilhados
```

## 7 Módulos Detalhados

7. Módulos Detalhados

7.1 Agent Loop

Executa os módulos em sequência, controla delays e ambiente.

7.2 Pre-Recon

Fingerprint de servidor, SSL, DNS, portas abertas.

7.3 Headers Analyzer

Analisa cabeçalhos, score de segurança e segurança passiva.

7.4 Parser

Coleta e analisa formulários, links, scripts e superfícies atacáveis.

7.5 Inject Finder

Testa pontos vulneráveis com payloads de injeção (XSS, SQLi, etc).

7.6 Fuzzer Adaptativo

Executa fuzzing com evasão de WAFs e rotação de headers.

7.7 Defense Detector

Detecta WAF, rate limit, CAPTCHA, CSRF, IP blocking.

7.8 Memory System

Cruza achados com banco interno de vulnerabilidades anteriores.

7.9 AI Interpreter

Aplica IA para interpretar resultados e sugerir próximos vetores.

⸻

8. Relatórios Gerados

8.1 Formatos
	•	JSON
	•	Markdown
	•	HTML
	•	PDF

8.2 Conteúdo
	•	Nível de risco
	•	Vetores explorados
	•	Payloads e evidências
	•	Status das defesas
	•	Recomendação por prioridade

⸻

9. Considerações de Segurança

9.1 Uso Ético
	•	Use apenas com autorização
	•	Nunca execute em produção sem consentimento
	•	Guarde logs e evidências

9.2 Proteções Embutidas
	•	Respeito a robots.txt
	•	Modo stealth ativado
	•	Delay adaptativo por padrão
	•	Suporte a proxies e rotação de identidade

⸻

10. Contribuição

10.1 Como contribuir
	1.	Faça um fork
	2.	Crie uma branch
	3.	Commit suas alterações
	4.	Envie um Pull Request

10.2 Áreas sugeridas
	•	Novos módulos (ex: SSRF, RCE, LDAP, JWT)
	•	Expansão da IA embarcada
	•	Visualização via dashboard
	•	Exportação direta para plataformas (ex: HackerOne, Bugcrowd)

⸻

11. Changelog

v1.0.0 (Atual)
	•	Estrutura modular completa
	•	Execução por linha de comando
	•	Geração de relatórios multi-formato
	•	IA interpretativa integrada
	•	Fuzzer adaptativo
	•	Módulo de memória e aprendizado

⸻

12. Problemas Conhecidos
	•	IA depende de conexão com OpenAI (se habilitado)
	•	Geração de PDF requer instalação de reportlab
	•	Alguns WAFs com comportamento agressivo bloqueiam varreduras longas

⸻

13. Suporte
	•	Documentação neste arquivo (README.md)
	•	Comentários inline no código
	•	Issues abertas no GitHub
	•	Logs detalhados no diretório logs/

⸻

14. Licença

Distribuído sob a licença MIT.
Consulte o arquivo LICENSE para mais detalhes.

⸻

15. Disclaimer

O AEGIS Bug Hunter é uma ferramenta educacional e de pesquisa em segurança cibernética.
O uso é de inteira responsabilidade do usuário.
Nunca utilize contra sistemas que você não tem permissão.

⸻

AEGIS Bug Hunter v1.0.0
Desenvolvido com dedicação por Felipe Di Carlo, com foco em automação, IA e segurança ofensiva aplicada.

⸻
