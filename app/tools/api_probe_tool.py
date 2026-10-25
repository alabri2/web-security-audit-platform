import requests
from app.tools.base import BaseTool, ToolRunResult, ParsedFinding
class ApiProbeTool(BaseTool):
    name="api_probe"; category="fingerprint"; timeout=20; modes={"normal","advanced"}
    def build_command(self, target): return []
    def run(self, scan_id, target):
        findings=[]; output_parts=[]; test_paths=["/api","/api/v1","/swagger","/docs","/openapi.json","/swagger.json"]
        try:
            for path in test_paths:
                url=target.rstrip("/") + path
                try:
                    r=requests.get(url, timeout=5, verify=False)
                    output_parts.append(f"{url} -> {r.status_code} {r.headers.get('content-type', '')}")
                    if r.status_code == 200:
                        ctype=r.headers.get("content-type","").lower()
                        if "json" in ctype: findings.append(ParsedFinding(severity="info", title="Endpoint API détecté", description=f"Endpoint actif: {url}"))
                        if "swagger" in url or "openapi" in url or "docs" in url: findings.append(ParsedFinding(severity="info", title="Documentation API détectée", description=f"Documentation potentielle trouvée: {url}"))
                except Exception: pass
            return ToolRunResult(exit_code=0, output="\n".join(output_parts), findings=findings)
        except Exception as e:
            return ToolRunResult(exit_code=-1, output=str(e), findings=[ParsedFinding(severity="low", title="Erreur API probe", description=str(e))])
