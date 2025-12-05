import json

def dump_results_json(results: dict) -> str:
    return json.dumps(results, indent=2, sort_keys=True, ensure_ascii=False)
