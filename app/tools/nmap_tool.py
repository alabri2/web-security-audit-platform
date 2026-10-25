from app.tools.base import BaseTool, ToolRunResult, ParsedFinding
class NmapTool(BaseTool):
    name="nmap"; category="network"; timeout=120; modes={"normal","advanced"}
    def build_command(self, target):
        host=target.replace("http://","").replace("https://","").split("/")[0]; return ["nmap","-sV","-Pn",host]
    def parse_output(self, target, output):
        result=ToolRunResult(exit_code=0, output=output)
        for line in output.splitlines():
            line=line.strip()
            if "/tcp" in line or "/udp" in line:
                parts=line.split()
                if len(parts)>=3:
                    pp=parts[0]; state=parts[1]; service=parts[2]; version=" ".join(parts[3:]) if len(parts)>3 else ""
                    try:
                        port, proto = pp.split("/",1); result.services.append((target,int(port),proto,service,version,state))
                    except: pass
        result.findings.append(ParsedFinding(severity="info", title="Scan ports/services", description=output[:1000] if output else "Aucune sortie"))
        return result
