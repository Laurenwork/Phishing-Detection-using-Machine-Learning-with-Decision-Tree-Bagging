from flask import Flask, render_template, request, jsonify
import phishing_detection  
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/result')
def result():
    url = request.args.get('name', '')
    if not url:
        return "URL is required", 400
    try:
        result = phishing_detection.getResult(url)
        return result
    except Exception as e:
        return f"Error: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True)
from flask import Flask, request, jsonify
from phishing_detection import detect_phishing
from feature_extraction import extract_features

app = Flask(__name__)

@app.route("/check", methods=["POST"])
def check_url():
    data = request.json
    url = data.get("url")
    features = extract_features(url)
    result = detect_phishing(features)
    return jsonify({"result": result})

if __name__ == "__main__":
    app.run(debug=True)
