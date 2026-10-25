from dataclasses import dataclass, field
from typing import List, Optional
import subprocess
from app.config import OUTPUT_DIR

@dataclass
class ParsedFinding:
    severity: str
    title: str
    description: str
    asset: Optional[str] = None

@dataclass
class ToolRunResult:
    exit_code: int
    output: str
    findings: List[ParsedFinding] = field(default_factory=list)
    assets: List[tuple] = field(default_factory=list)
    services: List[tuple] = field(default_factory=list)
    technologies: List[tuple] = field(default_factory=list)

class BaseTool:
    name = "base"
    category = "generic"
    timeout = 60
    modes = {"normal","advanced"}

    def build_command(self, target: str):
        raise NotImplementedError

    def parse_output(self, target: str, output: str):
        return ToolRunResult(exit_code=0, output=output)

    def run(self, scan_id: str, target: str):
        cmd = self.build_command(target)
        if not cmd:
            return ToolRunResult(exit_code=0, output="")
        try:
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            output = (cp.stdout or "") + ("\n" + cp.stderr if cp.stderr else "")
            result = self.parse_output(target, output)
            result.exit_code = cp.returncode
        except FileNotFoundError:
            output = f"Command not found: {cmd[0]}"
            result = ToolRunResult(exit_code=-1, output=output, findings=[ParsedFinding(severity="info", title=f"{self.name} unavailable", description=output)])
        except subprocess.TimeoutExpired:
            output = f"Timeout after {self.timeout}s: {' '.join(cmd)}"
            result = ToolRunResult(exit_code=-1, output=output, findings=[ParsedFinding(severity="low", title=f"{self.name} timeout", description=output)])
        except Exception as e:
            output = f"Error: {e}"
            result = ToolRunResult(exit_code=-1, output=output, findings=[ParsedFinding(severity="low", title=f"{self.name} error", description=output)])
        out_dir = OUTPUT_DIR / scan_id
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{self.name}.txt").write_text(result.output, encoding="utf-8")
        return result
