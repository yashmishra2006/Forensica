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

# --- CONFIG ---
DEVICE_NAME = "test"
DEVICE_PATH = os.path.join("devices", DEVICE_NAME)
OUTPUT_PATH = os.path.join(DEVICE_PATH, "output.json")
THREAT_KEYWORDS = ['bomb', 'explosive', 'password', 'credentials', 'attack', 'kill', 'terror', 'guns']

# --- INIT ---
app = Flask(__name__)
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
model = resnet50(weights=ResNet50_Weights.DEFAULT)
model.eval()

# Load ImageNet labels
LABELS = []
with open("imagenet_classes.txt", "r") as f:
    LABELS = [line.strip() for line in f.readlines()]

transform = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.ToTensor(),
])

# --- UTILITIES ---

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
    flagged_entries = []

    for entry in data:
        found_keywords = []
        content = entry.get('content', '').lower()
        for word in THREAT_KEYWORDS:
            if re.search(rf"\b{re.escape(word)}\b", content):
                found_keywords.append(word)
        if found_keywords:
            threats_found = True
            entry['threat_keywords'] = found_keywords
            flagged_entries.append(entry)

    return threats_found, flagged_entries

# --- ROUTES ---

@app.route("/")
def index():
    # Step 1: Scan files and generate output.json
    print("[✓] Running analysis...")
    output = scan_directory(DEVICE_NAME)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"[✓] Analysis complete. Output saved to {OUTPUT_PATH}")

    # Step 2: Load output.json and scan for threats
    with open(OUTPUT_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    threats_found, flagged_entries = scan_threats(data)

    return render_template("index.html", data=data, threats_found=threats_found, threats=flagged_entries)

# --- MAIN ---
if __name__ == "__main__":
    app.run(debug=True)
