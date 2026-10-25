from app.tools.base import BaseTool, ToolRunResult, ParsedFinding
class SslscanTool(BaseTool):
    name="sslscan"; category="tls"; timeout=60; modes={"normal"}
    def build_command(self, target):
        host=target.replace("http://","").replace("https://","").split("/")[0]; return ["sslscan",host]
    def parse_output(self, target, output):
        return ToolRunResult(exit_code=0, output=output, findings=[ParsedFinding(severity="info", title="Analyse TLS/SSL", description=output[:1200] or "Aucune sortie")])
