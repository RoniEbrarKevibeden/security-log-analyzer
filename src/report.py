import json
from typing import Any, Dict, List


def write_json(findings: List[Dict[str, Any]], out_path: str) -> None:
    payload = {
        "findings": findings,
        "total_findings": len(findings),
    }

    with open(out_path, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2)