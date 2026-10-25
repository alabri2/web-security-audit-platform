from app.tools.base import BaseTool, ToolRunResult, ParsedFinding
class DalfoxTool(BaseTool):
    name="dalfox"; category="vulnerability"; timeout=180; modes={"advanced"}
    def build_command(self, target): return ["dalfox","url",target,"--only-discover"]
    def parse_output(self, target, output):
        severity="medium" if output.strip() else "info"
        return ToolRunResult(exit_code=0, output=output, findings=[ParsedFinding(severity=severity, title="Dalfox résultat", description=output[:1200] or "Aucune sortie")])
