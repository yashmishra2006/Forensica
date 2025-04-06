import csv
import json
from rapidfuzz import fuzz

SEARCH_FILE = "search.txt"
JSON_INPUT_FILE = "devices/test/output.json"
OUTPUT_CSV = "search_results.csv"

def read_search_terms():
    try:
        with open(SEARCH_FILE, "r", encoding="utf-8") as f:
            return [term.strip() for term in f.read().split(",") if term.strip()]
    except FileNotFoundError:
        print("❌ search.txt not found.")
        return [] 

def search_in_json(data, terms, writer):
    found = set()

    if not isinstance(data, list):
        data = [data]

    for entry in data:
        file_path = entry.get("path", "unknown")
        content = entry.get("content", "")
        tags = entry.get("tags", [])
        sensitive_info = entry.get("sensitive_info", {})
        flags = sensitive_info.get("flags", [])
        detected = sensitive_info.get("detected_entities", {})

        # Search in content
        for term in terms:
            if term.lower() in content.lower() and (term, file_path, "content") not in found:
                writer.writerow([term, file_path, "content", "Exact"])
                found.add((term, file_path, "content"))
            else:
                score = fuzz.partial_ratio(term.lower(), content.lower())
                if score >= 85 and (f"~{term}", file_path, "content") not in found:
                    writer.writerow([f"~{term}", file_path, "content", f"Fuzzy ({score})"])
                    found.add((f"~{term}", file_path, "content"))

        # Search in tags
        for tag in tags:
            for term in terms:
                if term.lower() in tag.lower() and (term, file_path, "tag") not in found:
                    writer.writerow([term, file_path, "tag", "Exact"])
                    found.add((term, file_path, "tag"))
                else:
                    score = fuzz.partial_ratio(term.lower(), tag.lower())
                    if score >= 85 and (f"~{term}", file_path, "tag") not in found:
                        writer.writerow([f"~{term}", file_path, "tag", f"Fuzzy ({score})"])
                        found.add((f"~{term}", file_path, "tag"))

        # Search in flags
        for flag in flags:
            for term in terms:
                if term.lower() in flag.lower() and (term, file_path, "flag") not in found:
                    writer.writerow([term, file_path, "flag", "Exact"])
                    found.add((term, file_path, "flag"))
                else:
                    score = fuzz.partial_ratio(term.lower(), flag.lower())
                    if score >= 85 and (f"~{term}", file_path, "flag") not in found:
                        writer.writerow([f"~{term}", file_path, "flag", f"Fuzzy ({score})"])
                        found.add((f"~{term}", file_path, "flag"))

        # Search in detected_entities
        for key, values in detected.items():
            # bool (e.g. base64_strings)
            if isinstance(values, bool):
                continue
            for value in values:
                for term in terms:
                    if term.lower() in value.lower() and (term, file_path, key) not in found:
                        writer.writerow([term, file_path, key, "Exact"])
                        found.add((term, file_path, key))
                    else:
                        score = fuzz.partial_ratio(term.lower(), value.lower())
                        if score >= 85 and (f"~{term}", file_path, key) not in found:
                            writer.writerow([f"~{term}", file_path, key, f"Fuzzy ({score})"])
                            found.add((f"~{term}", file_path, key))

def main():
    terms = read_search_terms()
    if not terms:
        return

    try:
        with open(JSON_INPUT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as out_csv:
            writer = csv.writer(out_csv)
            writer.writerow(["Term", "File", "Section", "Match Type"])
            search_in_json(data, terms, writer)

        print(f"\n✅ Done! Results in {OUTPUT_CSV}")

    except Exception as e:
        print(f"❌ Error reading or processing JSON file: {e}")

if __name__ == "__main__":
    main()
