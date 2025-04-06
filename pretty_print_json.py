import json
import sys
from pathlib import Path

def pretty_print_json(json_path):
    try:
        path = Path(json_path)
        if not path.exists():
            print(f"[!] File not found: {json_path}")
            return
        
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        print(json.dumps(data, indent=4, ensure_ascii=False))

    except json.JSONDecodeError as e:
        print(f"[!] Failed to decode JSON: {e}")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pretty_print_json.py <path_to_json_file>")
    else:
        pretty_print_json(sys.argv[1])
