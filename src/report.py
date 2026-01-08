import json
from typing import List, Dict, Any

def write_json(findings: List[Dict[str, Any]], out_path: str) -> None:
    payload = {"findings": findings, "total_findings": len(findings)}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
