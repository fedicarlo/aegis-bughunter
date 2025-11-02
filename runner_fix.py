#!/usr/bin/env python3
# runner_fix.py -- wrapper para executar módulos do Aegis garantindo output_dir
import os
import importlib
from datetime import datetime

# importe o módulo run original se precisar de helpers
# import run as original_run

# lista de módulos pelo nome importável (ajuste se nomes de pacotes forem diferentes)
MODULES = [
    "aegis.agent_loop",
    "aegis.pre_recon",
    "aegis.headers_analyzer",
    "aegis.parser",
    "aegis.inject_finder",
    "aegis.fuzzer",
    "aegis.defense_detector",
    "aegis.memory_system",
    "aegis.ai_interpreter",
    "aegis.estado_printer",
    "aegis.report_gen",
    "aegis.reporter",
]

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def run_target(target_url, base_output_dir="output"):
    hostname = target_url.replace("https://", "").replace("http://", "").split("/")[0]
    output_dir = os.path.join(base_output_dir, hostname)
    ensure_dir(output_dir)

    mod_status = {}
    for mod_path in MODULES:
        name = mod_path.split(".")[-1]
        try:
            mod = importlib.import_module(mod_path)
        except Exception as e:
            print(f"[{name}] ❌ import error: {e}")
            mod_status[name] = f"import_error: {e}"
            continue

        print(f"[{name}] ➡️ Executando módulo: {name}")
        try:
            # tenta assinatura: executar(target_url, output_dir=...)
            try:
                mod.executar(target_url, output_dir=output_dir)
            except TypeError:
                try:
                    mod.executar(target_url, output_dir)
                except TypeError:
                    mod.executar(target_url)
            mod_status[name] = "✅"
        except Exception as e:
            print(f"[{name}] ❌ Falha ao executar '{name}': {e}")
            mod_status[name] = f"❌ {e}"

    # salvar status
    status_file = os.path.join(output_dir, "status_analise.json")
    import json
    with open(status_file, "w") as f:
        json.dump({"modulos": mod_status}, f, indent=2)
    print(f"[runner_fix] ✅ Fluxo finalizado. Resultado em: {output_dir}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python runner_fix.py https://alvo.example")
        sys.exit(1)
    run_target(sys.argv[1])
