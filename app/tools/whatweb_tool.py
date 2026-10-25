from app.tools.base import BaseTool, ToolRunResult, ParsedFinding
class WhatwebTool(BaseTool):
    name="whatweb"; category="fingerprint"; timeout=20; modes={"normal","advanced"}
    def build_command(self, target): return ["whatweb", target]
    def parse_output(self, target, output):
        result=ToolRunResult(exit_code=0, output=output); lowered=(output or "").lower()
        result.findings.append(ParsedFinding(severity="info", title="Technologies détectées", description=output[:1000] if output else "Aucune sortie"))
        if "wordpress" in lowered or "wp-content" in lowered:
            result.findings.append(ParsedFinding(severity="info", title="CMS détecté: WordPress", description="Le fingerprinting indique que la cible utilise WordPress."))
        if "application/json" in lowered or "openapi" in lowered or "swagger" in lowered:
            result.findings.append(ParsedFinding(severity="info", title="Type détecté: API", description="La cible semble exposer une API ou une documentation Swagger/OpenAPI."))
        for part in output.split(","):
            part=part.strip()
            if part and "[" in part:
                name=part.split("[",1)[0].strip(); version=part.split("[",1)[1].rstrip("]").strip(); result.technologies.append((target,name,version))
            elif part:
                result.technologies.append((target,part,""))
        return result
