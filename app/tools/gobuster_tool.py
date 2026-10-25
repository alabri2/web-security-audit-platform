from app.tools.base import BaseTool, ToolRunResult, ParsedFinding
class GobusterTool(BaseTool):
    name="gobuster"; category="enumeration"; timeout=120; modes={"advanced"}
    def build_command(self, target): return ["gobuster","dir","-u",target,"-w","/usr/share/wordlists/dirb/common.txt","-q"]
    def parse_output(self, target, output):
        return ToolRunResult(exit_code=0, output=output, findings=[ParsedFinding(severity="medium", title="Répertoires / endpoints détectés", description=output[:1200] or "Aucune sortie")])
