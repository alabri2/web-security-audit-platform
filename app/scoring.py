SEVERITY_POINTS = {"critical":25,"high":15,"medium":8,"low":3,"info":1}
TOOL_WEIGHT = {"sqlmap":1.5,"nuclei":1.4,"dalfox":1.3,"wpscan":1.3,"nikto":1.1,"nmap":1.1}

def calculate_score(findings):
    score = 100.0
    for f in findings:
        sev = str(f.get("severity","info")).lower()
        tool = str(f.get("tool","")).lower()
        score -= SEVERITY_POINTS.get(sev,1) * TOOL_WEIGHT.get(tool,1.0)
    return max(0, round(score))

def get_security_level(score:int)->str:
    if score >= 90: return "Excellent"
    if score >= 75: return "Good"
    if score >= 50: return "Medium"
    if score >= 25: return "Poor"
    return "Critical"
