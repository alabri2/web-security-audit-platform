from app.tools.base import BaseTool, ToolRunResult, ParsedFinding
class DirsearchTool(BaseTool):
    name="dirsearch"; category="enumeration"; timeout=180; modes={"advanced"}
    def build_command(self, target): return ["dirsearch","-u",target,"-e","php,html,js,txt","--simple-report=-"]
    def parse_output(self, target, output):
        findings=[]
        if output.strip(): findings.append(ParsedFinding(severity="medium", title="Chemins / fichiers détectés", description=output[:1500]))
        else: findings.append(ParsedFinding(severity="info", title="Dirsearch terminé", description="Aucun chemin intéressant détecté."))
        return ToolRunResult(exit_code=0, output=output, findings=findings)
