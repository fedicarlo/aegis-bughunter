#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import inspect
from datetime import datetime
from urllib.parse import urlparse

from aegis.agent_loop import executar as agent_loop
from aegis.pre_recon import executar as pre_recon
from aegis.headers_analyzer import executar as headers_analyzer
from aegis.parser import executar as parser_mod
from aegis.inject_finder import executar as inject_finder
from aegis.fuzzer import executar as fuzzer
from aegis.defense_detector import executar as defense_detector
from aegis.memory_system import executar as memory_system
from aegis.ai_interpreter import executar as ai_interpreter
from aegis.estado_printer import executar as estado_printer
from aegis.report_gen import executar as report_gen
from aegis.reporter import executar as reporter

BANNER = r"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                    🛡️  AEGIS BUG HUNTER 🛡️                    ║
    ║                                                               ║
    ║           Sistema Autônomo de Bug Bounty com IA              ║
    ║              "O hacker que nunca dorme"                      ║
    ╚═══════════════════════════════════════════════════════════════╝
"""

def norm_target(raw):
    raw = raw.strip()
    if not raw.startswith(("http://","https://")):
        raw = "https://" + raw
    return raw

def outdir_for(target):
    host = urlparse(target).hostname or "alvo"
    d = os.path.join("output", host)
    os.makedirs(d, exist_ok=True)
    return d

def call_module(mod_fn, target, outdir):
    """
    Chama executar(...) de forma inteligente:
    - se aceitar (target, outdir) passa ambos
    - se aceitar (target) passa só o alvo
    - se não aceitar nada, chama sem args
    """
    try:
        sig = inspect.signature(mod_fn)
        params = list(sig.parameters.values())
        if len(params) >= 2:
            return mod_fn(target, outdir)
        elif len(params) == 1:
            return mod_fn(target)
        else:
            return mod_fn()
    except Exception as e:
        raise

def main():
    print(BANNER)
    if len(sys.argv) > 1 and sys.argv[1] in ("-h","--help"):
        print("Uso: python run.py  (modo interativo)")
        sys.exit(0)

    alvo = input("🌐 Digite o alvo para iniciar (ex: https://exemplo.com): ").strip()
    if not alvo:
        print("Nada informado. Saindo.")
        return
    alvo = norm_target(alvo)
    print(f"\n🎯 Alvo selecionado: {alvo}")
    cont = input("Deseja continuar? (s/n): ").strip().lower()
    if cont != "s":
        print("Cancelado.")
        return

    output_dir = outdir_for(alvo)
    print("\n============================================================")
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] 🧠 Iniciando fluxo completo contra: {alvo}")

    pipeline = [
        ("agent_loop", agent_loop),
        ("pre_recon", pre_recon),
        ("headers_analyzer", headers_analyzer),
        ("parser", parser_mod),
        ("inject_finder", inject_finder),
        ("fuzzer", fuzzer),
        ("defense_detector", defense_detector),
        ("memory_system", memory_system),
        ("ai_interpreter", ai_interpreter),
        ("estado_printer", estado_printer),
        ("report_gen", report_gen),
        ("reporter", reporter),
    ]

    ok = 0
    fail = []
    for name, fn in pipeline:
        start = time.time()
        print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] ➡️ Executando módulo: {name}")
        try:
            call_module(fn, alvo, output_dir)
            dur = time.time() - start
            print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] ✅ Módulo '{name}' executado com sucesso ({dur:.2f}s)")
            ok += 1
        except Exception as e:
            print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] ❌ Falha ao executar '{name}': {e}")
            fail.append((name, str(e)))

    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] 🏁 Fluxo de execução finalizado")
    print("============================================================\n")
    print("📊 RESUMO DA EXECUÇÃO:")
    print(f"✅ Módulos executados com sucesso: {ok}")
    print(f"❌ Módulos com erro: {len(fail)}")
    if fail:
        print("\n🔍 Módulos com erro:")
        for n, msg in fail:
            print(f"  - {n}: {msg}")

    print(f"\n📁 Resultados salvos em: {output_dir}/")
    print("📋 Logs de execução salvos em: logs/execucao.log" if os.path.exists("logs/execucao.log") else "")

if __name__ == "__main__":
    main()
