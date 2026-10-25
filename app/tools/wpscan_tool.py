from app.tools.base import BaseTool, ToolRunResult, ParsedFinding
class WPScanTool(BaseTool):
    name="wpscan"; category="vulnerability"; timeout=180; modes={"advanced"}
    def build_command(self, target): return ["wpscan","--url",target,"--enumerate","vp,vt,u"]
    def parse_output(self, target, output):
        findings=[]; lowered=(output or "").lower()
        if "wordpress version" in lowered: findings.append(ParsedFinding(severity="info", title="Version WordPress détectée", description="WPScan a identifié la version de WordPress."))
        if "vulnerable" in lowered or "vulnerability" in lowered: findings.append(ParsedFinding(severity="high", title="Vulnérabilités WordPress potentielles", description=output[:1500] if output else "Aucune sortie"))
        else: findings.append(ParsedFinding(severity="info", title="Résultat WPScan", description=output[:1500] if output else "Aucune sortie"))
        return ToolRunResult(exit_code=0, output=output, findings=findings)
