# pre_recon.py (patch) - garante função executar(target_url, output_dir)
import os
import requests
from urllib.parse import urlparse

def executar(target_url, output_dir=None):
    """
    Assinatura padronizada: executar(target_url, output_dir)
    Se modules antigos chamarem sem output_dir, runner faz fallback.
    """
    if output_dir is None:
        output_dir = os.path.join("output", urlparse(target_url).hostname)
    os.makedirs(output_dir, exist_ok=True)

    try:
        print(f"[pre_recon] 🧠 Iniciando reconhecimento de {target_url}")
        resp = requests.get(target_url, timeout=10, allow_redirects=True)
        headers_info = {
            "status_code": resp.status_code,
            "response_time": int(resp.elapsed.total_seconds()*1000),
            "headers": dict(resp.headers)
        }
        print(f"[pre_recon] 📡 Coletando headers de {target_url}")
        print(f"[pre_recon] ✅ Status: {resp.status_code} | Tempo: {headers_info['response_time']}ms")
        # verifica SSL (simples)
        try:
            import ssl, socket
            hostname = urlparse(target_url).hostname
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
            cert_info = {"tem_ssl": True, "emissor": cert.get('issuer')}
        except Exception as e:
            cert_info = {"tem_ssl": False, "erro": str(e)}
            print(f"[pre_recon] ⚠️ Erro ao verificar SSL: {str(e)}")

        resultado = {
            "target": target_url,
            "resumo": {
                "status": resp.status_code,
                "response_time_ms": headers_info["response_time"],
                "tem_ssl": cert_info.get("tem_ssl", False),
                "emissor": cert_info.get("emissor", None),
            }
        }
        out_file = os.path.join(output_dir, "pre_recon.json")
        import json
        with open(out_file, "w") as f:
            json.dump(resultado, f, indent=2)
        print(f"[pre_recon] ✅ Reconhecimento finalizado")
        print(f"[pre_recon] 💾 Resultado salvo em: {out_file}")
    except Exception as e:
        print(f"[pre_recon] ❌ Erro inesperado: {e}")
