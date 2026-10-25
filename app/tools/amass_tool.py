from app.tools.base import BaseTool, ToolRunResult, ParsedFinding
class AmassTool(BaseTool):
    name="amass"; category="recon"; timeout=180; modes={"advanced"}
    def build_command(self, target):
        domain=target.replace("http://","").replace("https://","").split("/")[0]; return ["amass","enum","-passive","-d",domain]
    def parse_output(self, target, output):
        result=ToolRunResult(exit_code=0, output=output)
        for line in output.splitlines():
            val=line.strip()
            if val: result.assets.append(("subdomain",val))
        result.findings.append(ParsedFinding(severity="info", title="Subdomains détectés via amass", description=f"{len(result.assets)} subdomains trouvés"))
        return result
