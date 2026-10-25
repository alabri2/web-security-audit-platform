import requests
from app.tools.base import BaseTool, ToolRunResult, ParsedFinding
class HeadersTool(BaseTool):
    name="headers"; category="fingerprint"; timeout=20; modes={"normal","advanced"}
    def build_command(self, target): return []
    def run(self, scan_id, target):
        try:
            response=requests.get(target, timeout=self.timeout, verify=False); headers=response.headers; findings=[]
            for h in ["Content-Security-Policy","X-Frame-Options","X-Content-Type-Options","Strict-Transport-Security","Referrer-Policy"]:
                if h not in headers: findings.append(ParsedFinding(severity="low", title=f"Header manquant: {h}", description=f"Le header de sécurité {h} n'est pas présent."))
            output="\n".join([f"{k}: {v}" for k,v in headers.items()])
            return ToolRunResult(exit_code=0, output=output, findings=findings)
        except Exception as e:
            return ToolRunResult(exit_code=-1, output=str(e), findings=[ParsedFinding(severity="low", title="Erreur lors de la lecture des headers", description=str(e))])
