from app.tools.whatweb_tool import WhatwebTool
from app.tools.nmap_tool import NmapTool
from app.tools.nikto_tool import NiktoTool
from app.tools.sslscan_tool import SslscanTool
from app.tools.amass_tool import AmassTool
from app.tools.subfinder_tool import SubfinderTool
from app.tools.gobuster_tool import GobusterTool
from app.tools.dirsearch_tool import DirsearchTool
from app.tools.nuclei_tool import NucleiTool
from app.tools.sqlmap_tool import SqlmapTool
from app.tools.dalfox_tool import DalfoxTool
from app.tools.headers_tool import HeadersTool
from app.tools.api_probe_tool import ApiProbeTool
from app.tools.wpscan_tool import WPScanTool

FINGERPRINT_TOOLS = [WhatwebTool(), HeadersTool(), ApiProbeTool()]

def get_tools_for_mode(mode: str):
    normal = [WhatwebTool(), HeadersTool(), ApiProbeTool(), NmapTool(), NiktoTool(), SslscanTool()]
    advanced = [WhatwebTool(), HeadersTool(), ApiProbeTool(), SubfinderTool(), AmassTool(), GobusterTool(), DirsearchTool(), NmapTool(), NucleiTool(), SqlmapTool(), DalfoxTool()]
    return advanced if str(mode).lower() == "advanced" else normal

def get_fingerprint_tools():
    return FINGERPRINT_TOOLS

def get_tools_for_target_type(mode: str, target_type: str):
    mode = str(mode).lower()
    target_type = str(target_type).lower()

    base_normal = [WhatwebTool(), HeadersTool(), ApiProbeTool(), NmapTool(), NiktoTool(), SslscanTool()]
    generic_advanced = [SubfinderTool(), AmassTool(), GobusterTool(), DirsearchTool(), NmapTool(), NucleiTool()]
    wordpress_advanced = [WPScanTool(), DirsearchTool(), GobusterTool(), NucleiTool(), NiktoTool()]
    api_advanced = [ApiProbeTool(), NmapTool(), NucleiTool(), SqlmapTool(), DalfoxTool(), DirsearchTool()]

    if mode == "normal":
        if target_type == "wordpress":
            return [WhatwebTool(), HeadersTool(), NmapTool(), NiktoTool(), SslscanTool(), WPScanTool()]
        if target_type == "api":
            return [HeadersTool(), ApiProbeTool(), NmapTool(), NucleiTool(), SslscanTool()]
        return base_normal

    if target_type == "wordpress":
        return base_normal + wordpress_advanced
    if target_type == "api":
        return base_normal + api_advanced
    return base_normal + generic_advanced

def detect_target_type_from_output(output: str, target: str) -> str:
    text = (output or "").lower()
    target = (target or "").lower()
    wordpress_markers = ["wordpress", "wp-content", "wp-includes", "wp-login", "xmlrpc.php"]
    api_markers = ["application/json", "openapi", "swagger", "/api/", "json response", "rest api", '"openapi"', '"swagger"']

    for marker in wordpress_markers:
        if marker in text or marker in target:
            return "wordpress"

    for marker in api_markers:
        if marker in text or marker in target:
            return "api"

    return "generic"
