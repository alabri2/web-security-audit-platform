from app.tools.base import BaseTool, ToolRunResult, ParsedFinding
class NiktoTool(BaseTool):
    name="nikto"; category="vulnerability"; timeout=90; modes={"normal","advanced"}
    def build_command(self, target): return ["nikto","-h",target]
    def parse_output(self, target, output):
        return ToolRunResult(exit_code=0, output=output, findings=[ParsedFinding(severity="medium", title="Nikto output", description=output[:1500] or "Aucune sortie")])
