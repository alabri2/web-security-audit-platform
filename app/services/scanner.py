from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from app.config import MAX_WORKERS
from app.database import (
    create_scan, finish_scan, fail_scan, update_target_type,
    add_scan_tool, finish_scan_tool, add_asset, add_service,
    add_technology, add_finding, get_findings
)
from app.report import build_html_report, build_pdf_report
from app.scoring import calculate_score
from app.services.tool_registry import (
    get_fingerprint_tools,
    get_tools_for_target_type,
    detect_target_type_from_output
)
from app.utils.cleaner import clean_evidence, clean_title, clean_description


class ScannerService:
    def __init__(self):
        self.pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def enqueue(
        self,
        target: str,
        mode: str,
        authorized: bool,
        target_mode: str = "auto",
        target_type=None
    ) -> str:
        scan_id = str(uuid4())
        self.pool.submit(
            self._run_scan,
            scan_id,
            target,
            mode,
            authorized,
            target_mode,
            target_type
        )
        return scan_id

    def _store_result_findings(self, scan_id, tool_name, result):
        cleaned_output = clean_evidence(result.output or "")

        for finding in result.findings:
            title = clean_title(finding.title)
            description = clean_description(finding.description)

            # إذا ما فيه evidence من output، نخزن الوصف نفسه كحد أدنى
            evidence = cleaned_output or clean_evidence(finding.description or "")

            add_finding(
                scan_id,
                finding.asset,
                tool_name,
                finding.severity,
                title,
                description,
                evidence
            )

    def _run_scan(
        self,
        scan_id: str,
        target: str,
        mode: str,
        authorized: bool,
        target_mode: str,
        requested_target_type
    ):
        if not authorized:
            raise PermissionError("Scan non autorisé.")

        create_scan(
            scan_id,
            target,
            mode,
            authorization_confirmed=authorized,
            selection_mode=target_mode,
            requested_target_type=requested_target_type,
        )

        asset_cache = {}

        try:
            fingerprint_output = ""

            # Phase 1: fingerprint
            for tool in get_fingerprint_tools():
                add_scan_tool(scan_id, tool.name, "running")
                result = tool.run(scan_id, target)
                fingerprint_output += "\n" + (result.output or "")

                self._store_result_findings(scan_id, tool.name, result)

                for asset_type, value in result.assets:
                    if value not in asset_cache:
                        asset_cache[value] = add_asset(scan_id, asset_type, value)

                for asset_value, tech, version in result.technologies:
                    if asset_value not in asset_cache:
                        asset_cache[asset_value] = add_asset(scan_id, "host", asset_value)
                    add_technology(asset_cache[asset_value], tech, version)

                finish_scan_tool(
                    scan_id,
                    tool.name,
                    "finished" if result.exit_code == 0 else "error"
                )

            # Phase 2: classification
            if str(target_mode).lower() == "manual" and requested_target_type:
                final_target_type = requested_target_type
                add_finding(
                    scan_id,
                    None,
                    "classifier",
                    "info",
                    "Manual target type selection",
                    f"The user manually selected the target type: {requested_target_type}",
                    ""
                )
            else:
                final_target_type = detect_target_type_from_output(fingerprint_output, target)
                add_finding(
                    scan_id,
                    None,
                    "classifier",
                    "info",
                    "Automatic target type detection",
                    f"The system classified the target as: {final_target_type}",
                    clean_evidence(fingerprint_output)
                )

            update_target_type(scan_id, final_target_type)

            # Phase 3: target-specific tools
            already_run = {tool.name for tool in get_fingerprint_tools()}
            for tool in get_tools_for_target_type(mode, final_target_type):
                if tool.name in already_run:
                    continue

                add_scan_tool(scan_id, tool.name, "running")
                result = tool.run(scan_id, target)

                for asset_type, value in result.assets:
                    if value not in asset_cache:
                        asset_cache[value] = add_asset(scan_id, asset_type, value)

                for asset_value, port, proto, service, version, state in result.services:
                    if asset_value not in asset_cache:
                        asset_cache[asset_value] = add_asset(scan_id, "host", asset_value)
                    add_service(asset_cache[asset_value], port, proto, service, version, state)

                for asset_value, tech, version in result.technologies:
                    if asset_value not in asset_cache:
                        asset_cache[asset_value] = add_asset(scan_id, "host", asset_value)
                    add_technology(asset_cache[asset_value], tech, version)

                self._store_result_findings(scan_id, tool.name, result)

                finish_scan_tool(
                    scan_id,
                    tool.name,
                    "finished" if result.exit_code == 0 else "error"
                )

            # Phase 4: scoring + reports
            score = calculate_score(get_findings(scan_id))
            finish_scan(scan_id, score)

            html_path = build_html_report(scan_id)
            print(f"[REPORT] HTML generated: {html_path}")

            pdf_path = build_pdf_report(scan_id)
            print(f"[REPORT] PDF generated: {pdf_path}")

        except Exception as e:
            print(f"[SCAN ERROR] {e}")
            fail_scan(scan_id)
            raise
