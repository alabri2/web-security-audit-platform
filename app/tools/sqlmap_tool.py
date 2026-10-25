from app.tools.base import BaseTool, ToolRunResult, ParsedFinding
class SqlmapTool(BaseTool):
    name="sqlmap"; category="vulnerability"; timeout=240; modes={"advanced"}
    def build_command(self, target): return ["sqlmap","-u",target,"--batch","--level=1"]
    def parse_output(self, target, output):
        severity="high" if "injection" in output.lower() else "info"
        return ToolRunResult(exit_code=0, output=output, findings=[ParsedFinding(severity=severity, title="SQLMap résultat", description=output[:1500] or "Aucune sortie")])
