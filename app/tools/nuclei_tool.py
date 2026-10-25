from app.tools.base import BaseTool, ToolRunResult, ParsedFinding
class NucleiTool(BaseTool):
    name="nuclei"; category="vulnerability"; timeout=180; modes={"advanced"}
    def build_command(self, target): return ["nuclei","-u",target,"-silent"]
    def parse_output(self, target, output):
        result=ToolRunResult(exit_code=0, output=output); lines=[x.strip() for x in output.splitlines() if x.strip()]
        if not lines: result.findings.append(ParsedFinding(severity="info", title="Nuclei", description="Aucune vulnérabilité détectée"))
        else:
            for line in lines[:50]: result.findings.append(ParsedFinding(severity="high", title="Nuclei finding", description=line))
        return result
