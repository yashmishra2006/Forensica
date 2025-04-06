import os
import json
import pytesseract
import torch
import base64
import re
import fitz  # PyMuPDF
from PIL import Image
from flask import Flask, render_template
import torchvision.transforms as transforms
from torchvision.models import resnet50, ResNet50_Weights
from flask import request, jsonify
from rapidfuzz import fuzz
from flask import Flask, render_template, jsonify
import json


# --- CONFIG ---
DEVICE_NAME = "test"
DEVICE_PATH = os.path.join("devices", DEVICE_NAME)
OUTPUT_PATH = os.path.join(DEVICE_PATH, "output.json")

THREAT_CATEGORIES = {
    "Financial Fraud": ["bank details", "credit card", "cvv", "password"],
    "Identity Theft": ["aadhar", "pan", "passport", "ssn", "dl"],
    "Weapons/Violence": ["gun", "rifle", "grenade", "explosives"],
    "Drugs/Illegal": ["syringe","cocaine", "weed", "heroin", "meth"],
    "Explicit Content": ["18+", "xxx", "nsfw"],
    "Terrorism Keywords": ["bomb", "attack", "isis", "recruitment"],
    "Surveillance Data": ["location", "recording", "camera", "tracking"],
    "Encrypted/Hidden": ["encrypted", "password-protected", "zip"]
}

# --- INIT ---
app = Flask(__name__)
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
model = resnet50(weights=ResNet50_Weights.DEFAULT)
model.eval()

search_results_cache = []
flagged_entries = []

LABELS = []
with open("imagenet_classes.txt", "r") as f:
    LABELS = [line.strip() for line in f.readlines()]

transform = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.ToTensor(),
])

# --- UTILITIES ---

# Somewhere near the top of app.py
import json
from flask import render_template

# Define this function so it's available anywhere
def load_all_data():
    with open(OUTPUT_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    threats_found, flagged_entries = scan_threats(data)
    return flagged_entries  # return only what you need


def is_base64(s):
    try:
        if len(s) % 4 == 0 and len(s) > 20:
            base64.b64decode(s, validate=True)
            return True
    except Exception:
        return False
    return False

def detect_sensitive_data(text):
    emails = re.findall(r"[\w.-]+@[\w.-]+", text)
    phones = re.findall(r"\+?\d[\d\-\s]{8,}\d", text)
    urls = re.findall(r"https?://\S+", text)
    base64_strings = any(is_base64(word) for word in text.split())

    flags = []
    if emails: flags.append("email_detected")
    if phones: flags.append("phone_detected")
    if urls: flags.append("url_detected")
    if base64_strings: flags.append("base64_suspicion")

    return {
        "flags": flags,
        "detected_entities": {
            "emails": emails,
            "phones": phones,
            "urls": urls,
            "base64_strings": base64_strings
        }
    }

def analyze_file(path):
    entry = {
        "path": path,
        "type": "",
        "content": "",
        "tags": [],
        "sensitive_info": {}
    }

    if path.lower().endswith(('.png', '.jpg', '.jpeg')):
        entry["type"] = "image"
        try:
            img = Image.open(path).convert('RGB')
            text = pytesseract.image_to_string(img).strip()
            entry["content"] = text

            input_tensor = transform(img).unsqueeze(0)
            with torch.no_grad():
                outputs = model(input_tensor)
                _, indices = torch.topk(outputs, 3)
                entry["tags"] = [LABELS[i] for i in indices[0]]
        except Exception as e:
            entry["content"] = f"Error: {e}"

    elif path.lower().endswith(".pdf"):
        entry["type"] = "pdf"
        try:
            doc = fitz.open(path)
            text = "\n".join([page.get_text() for page in doc])
            entry["content"] = text
        except Exception as e:
            entry["content"] = f"Error: {e}"

    else:
        entry["type"] = "file"
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            entry["content"] = text
        except Exception as e:
            entry["content"] = f"Error: {e}"

    entry["sensitive_info"] = detect_sensitive_data(entry["content"])
    return entry

def scan_directory(device_name):
    directory = os.path.join("devices", device_name)
    results = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file == "output.json":
                continue
            full_path = os.path.join(root, file)
            results.append(analyze_file(full_path))
    return results

def scan_threats(data):
    threats_found = False

    for entry in data:
        content = entry.get('content', '').lower()
        tags = " ".join(entry.get('tags', [])).lower()  # <-- Include tags
        combined_text = f"{content} {tags}"  # <-- Combine content + tags

        matched_categories = []

        for category, keywords in THREAT_CATEGORIES.items():
            for keyword in keywords:
                if re.search(rf"\b{re.escape(keyword)}\b", combined_text):  # <-- Scan combined text
                    matched_categories.append(category)
                    break  # One keyword match is enough per category

        if matched_categories:
            threats_found = True
            entry['threat_keywords'] = matched_categories
            entry['threat_class'] = matched_categories
            flagged_entries.append(entry)

    return threats_found, flagged_entries


# --- ROUTES ---

@app.route("/")
def index():
    print("[✓] Running analysis...")
    output = scan_directory(DEVICE_NAME)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"[✓] Analysis complete. Output saved to {OUTPUT_PATH}")

    with open(OUTPUT_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    threats_found, flagged_entries = scan_threats(data)

    return render_template("index.html", data=flagged_entries, threats_found=threats_found)

@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/charts")
def charts():
    return render_template("charts.html")

@app.route("/chart-data")
def chart_data():
    try:
        with open("devices/test/output.json", "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return jsonify({"error": f"Error reading output.json: {e}"}), 500

    # Reuse scanning function
    _, flagged_entries = scan_threats(data)

    category_count = {}
    for entry in flagged_entries:
        for cat in entry.get("threat_class", []):
            category_count[cat] = category_count.get(cat, 0) + 1

    return jsonify(category_count)


@app.route("/upload")
def home():
    return render_template("home.html")

@app.route("/results")
def results():
    return render_template("results.html", results=search_results_cache)


@app.route("/search")
def search():
    return render_template("search.html")

@app.route('/table')
def table():
    category = request.args.get('category')
    full_data = load_all_data()

    if category:
        filtered_data = [item for item in full_data if category in item['threat_class']]
        threats_found = len(filtered_data) > 0
    else:
        filtered_data = []
        threats_found = False

    print(filtered_data, threats_found)

    return render_template('table.html', data=filtered_data, threats_found=threats_found)


@app.route("/search_keywords", methods=["POST"])
def search_keywords():
    global search_results_cache
    data = request.get_json()
    keyword = data.get("keyword", "").strip().lower()
    file_type_filter = data.get("file_type", "all").lower()

    # 🔒 Prevent empty search
    if not keyword:
        search_results_cache = []
        return jsonify({"results": []})

    try:
        with open("devices/test/output.json", "r", encoding="utf-8") as f:
            json_data = json.load(f)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    results = []

    for entry in json_data:
        file_path = entry.get("path", "unknown")
        file_type = entry.get("type", "unknown")
        if file_type_filter != "all" and file_type != file_type_filter:
            continue

        content = entry.get("content", "").lower()
        tags = " ".join(entry.get("tags", [])).lower()
        flags = " ".join(entry.get("sensitive_info", {}).get("flags", [])).lower()
        entities = " ".join(
            [str(val) for val in entry.get("sensitive_info", {}).get("detected_entities", {}).values() if isinstance(val, list)]
        ).lower()

        match_type = None
        preview = ""

        if keyword in content:
            match_type = "Exact"
            preview = content[:200] + "..." if len(content) > 200 else content
        elif fuzz.partial_ratio(keyword, content) >= 85:
            match_type = f"Fuzzy ({fuzz.partial_ratio(keyword, content)})"
            preview = content[:200] + "..." if len(content) > 200 else content
        elif fuzz.partial_ratio(keyword, tags) >= 85:
            match_type = f"Fuzzy ({fuzz.partial_ratio(keyword, tags)})"
            preview = tags
        elif fuzz.partial_ratio(keyword, flags) >= 85:
            match_type = f"Fuzzy ({fuzz.partial_ratio(keyword, flags)})"
            preview = flags
        elif fuzz.partial_ratio(keyword, entities) >= 85:
            match_type = f"Fuzzy ({fuzz.partial_ratio(keyword, entities)})"
            preview = entities

        if match_type:
            results.append({
                "word": keyword,
                "fileType": file_type,
                "filePath": file_path,
                "section": "content/tags/flags/entities",
                "matchType": match_type,
                "preview": preview
            })

    search_results_cache = results
    return jsonify({"results": results})



# --- MAIN ---
if __name__ == "__main__":
    app.run(debug=True)
