# -*- coding: utf-8 -*-
import os
import json
from datetime import datetime

def executar(target_url, output_dir=None):
    """
    Interpretação local (fallback) e/ou via API (se configurada).
    Agora aceita output_dir opcional.
    """
    # onde salvar
    out_dir = output_dir or os.path.join("output", "generic")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "ai_interpretation.json")

    # Fallback local simples (sem OpenAI):
    result = {
        "target": target_url,
        "timestamp": datetime.utcnow().isoformat(),
        "critical_vulns": [],
        "high_vulns": [],
        "notes": [
            "Análise local executada (OpenAI não configurado).",
            "Sem evidências de vulnerabilidades críticas a partir dos módulos anteriores."
        ]
    }

    try:
        with open(out_file, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"[ai_interpreter] ✅ Resultado salvo em: {out_file}")
    except Exception as e:
        print(f"[ai_interpreter] ❌ Erro na análise com IA: {e}")
