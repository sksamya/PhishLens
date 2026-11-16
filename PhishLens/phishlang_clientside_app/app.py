import os
import threading
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
from transformers import MobileBertTokenizer, MobileBertForSequenceClassification
import torch
from bs4 import BeautifulSoup
import requests

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Resolve model path
current_dir = Path(__file__).resolve().parent
candidates = [
    current_dir / "src" / "model",
    current_dir / "PhishLens" / "src" / "model",
    current_dir / "mobilebert_model",
    current_dir / "PhishLens" / "mobilebert_model",
    current_dir.parent / "src" / "model",
]
model_dir = None
for c in candidates:
    if c.exists() and (c / "model.safetensors").exists():
        model_dir = c
        break

if not model_dir:
    raise FileNotFoundError("Could not locate model folder containing model.safetensors")

print(f"Loading MobileBERT model from: {model_dir}")
model = MobileBertForSequenceClassification.from_pretrained(str(model_dir))
tokenizer = MobileBertTokenizer.from_pretrained(str(model_dir))
print("Model loaded successfully!")

# Bot challenge and interstitial signature patterns
BOT_CHALLENGE_KEYWORDS = [
    'just a moment...',
    'attention required! | cloudflare',
    'security check',
    'verify you are human',
    'ddos-guard',
    'hcaptcha challenge',
    'recaptcha',
    'bot verification',
    'access denied',
    'checking your browser before accessing',
    'please complete the security check to access',
    'cf-browser-verification',
    'ray id:',
    'challenges.cloudflare.com',
    'turnstile.render'
]

# Function to fetch HTML content from a URL
def fetch_html(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        return {
            'text': response.text,
            'status_code': response.status_code,
            'final_url': response.url
        }
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else 500
        return {
            'text': e.response.text if e.response is not None else '',
            'status_code': status,
            'error': str(e)
        }
    except Exception as e:
        print(f"Error fetching URL {url}: {e}")
        return None

def check_interstitial_or_captcha(html_text, status_code=200):
    if status_code in (401, 403):
        return True, f"HTTP {status_code} Access Denied state"
    
    if not html_text:
        return False, None
        
    lower = html_text.lower()
    for kw in BOT_CHALLENGE_KEYWORDS:
        if kw in lower:
            return True, f"Security challenge detected ({kw})"
            
    return False, None

# Functions for parsing the HTML content
def generate_text_representation(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    elements = soup.find_all(['h1', 'h2', 'h3', 'p', 'a', 'ul', 'ol', 'li', 'title', 'footer', 'form', 'script', 'input', 'button', 'iframe', 'meta', 'map', 'area'])

    parsed_representation = []
    for element in elements:
        tag_name = element.name
        text_content = element.get_text(strip=True).lower() if element.get_text(strip=True) else "<EMPTY>"
        
        if tag_name == 'a':
            href = element.get('href', 'No URL provided')
            parsed_representation.append(f'LINK: {{ "text": "{text_content} link", "href": "{href}" }}')
        elif tag_name == 'input':
            if element.get('type') == 'checkbox':
                label_element = element.find_next('label')
                label_text = label_element.get_text(strip=True).lower() if label_element else "No label found"
                parsed_representation.append(f'CHECKBOX: {{ "label": "{label_text}", "input": {{ "type": "checkbox", "name": "{element.get("name")}", "text": "{element.get("text", "")}" }} }}')
            else:
                parsed_representation.append(f'INPUT: {{ "type": "{element.get("type")}", "name": "{element.get("name")}", "placeholder": "{element.get("placeholder", "")}" }}')
        elif tag_name == 'button':
            parsed_representation.append(f'BUTTON: {{ "text": "{text_content} button" }}')
        elif tag_name == 'label':
            parsed_representation.append(f'LABEL: {{ "for": "{element.get("for")}", "text": "{text_content} field" }}')
        elif tag_name == 'form':
            parsed_representation.append(f'FORM: {{ "name": "{element.get("name", "Form")}" }}')
        elif tag_name == 'footer':
            footer_links = []
            for link in element.find_all('a'):
                href = link.get('href', 'No URL provided')
                footer_links.append(f'{{ "text": "{link.get_text(strip=True)} link", "href": "{href}" }}')
            parsed_representation.append(f'FOOTER_LINKS: [{", ".join(footer_links)}]')
        elif tag_name in ['h1', 'h2', 'h3', 'p', 'ul', 'ol', 'li', 'title', 'iframe', 'meta', 'map', 'area']:
            parsed_representation.append(f'{tag_name.upper()}: {{ "text": "{text_content}" }}')
        elif tag_name == 'script':
            parsed_representation.append(f'SCRIPT: {{ "content": "{text_content}" }}')
    
    return ' '.join(parsed_representation)

def predict_phishing(html_content):
    processed_text = generate_text_representation(html_content)
    
    inputs = tokenizer.encode_plus(
        processed_text,
        add_special_tokens=True,
        max_length=512,
        return_token_type_ids=False,
        padding='max_length',
        truncation=True,
        return_attention_mask=True,
        return_tensors='pt'
    )

    model.eval()
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        predicted_class = torch.argmax(logits, dim=-1)

    return predicted_class.item()

# Health checks and status endpoints
@app.route('/', methods=['GET'])
def index():
    return jsonify({
        'status': 'ok',
        'message': 'PhishLens backend server is running',
        'ports': [5000, 5024]
    })

@app.route('/health', methods=['GET'])
@app.route('/status', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

# Prediction endpoints
@app.route('/check_url', methods=['POST'])
@app.route('/predict', methods=['POST'])
@app.route('/scan', methods=['POST'])
def check_url():
    data = request.get_json(silent=True) or {}
    url = data.get('url', '')
    raw_html = data.get('html')
    status_code = 200
    
    if not raw_html and url:
        fetched = fetch_html(url)
        if fetched:
            raw_html = fetched.get('text', '')
            status_code = fetched.get('status_code', 200)
    
    # Phase 5: Check for bot challenges, CAPTCHAs, or HTTP 401/403 access-denied states
    is_blocked, block_reason = check_interstitial_or_captcha(raw_html, status_code)
    if is_blocked:
        return jsonify({
            'result': 'unverified',
            'status': 'unverified',
            'is_interstitial_blocked': True,
            'reason': "We couldn't verify the destination page because access is blocked by a security check. Treat this destination as unverified and proceed cautiously.",
            'details': block_reason
        }), 200

    if raw_html:
        prediction = predict_phishing(raw_html)
        # 0 = safe/benign, 1 = phishing
        label_map = {0: 'safe', 1: 'phishing'}
        result = label_map.get(prediction, 'safe')
        return jsonify({
            'result': result,
            'prediction': prediction,
            'status': result
        })
    else:
        return jsonify({
            'result': 'unverified',
            'status': 'unverified',
            'warning': 'Unable to fetch page HTML'
        }), 200

def run_port(port):
    print(f"[*] Backend server listening on http://localhost:{port} and http://127.0.0.1:{port}")
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

if __name__ == '__main__':
    # Start on port 5024 in secondary thread
    t = threading.Thread(target=run_port, args=(5024,), daemon=True)
    t.start()
    # Start on port 5000 on primary thread
    run_port(5000)
