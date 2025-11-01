from flask import Flask, request, jsonify
import json, re

app = Flask(__name__)

@app.route("/analyze", methods=["POST"])

def GetUrlToScan():
    # Get the input of the user
    DataReceived = request.get_json()
    UrlToCheck = DataReceived.get("url")

    # Check the user's input with a REGEX
    RegexPatternHttps = "https?:\/\/[a-zA-Z0-9\-\.]+[a-zA-Z]{2,6}"
    RegexPatternHttp = "https?:\/\/[a-zA-Z0-9\-\.]+[a-zA-Z]{2,6}"

    # If the URL has been recognized then we can process to the analysis
    if re.match(RegexPatternHttps, UrlToCheck) or re.match(RegexPatternHttp, UrlToCheck):
        with open("ToCheck.json", 'w', encoding='utf-8') as f:
            json.dump({"url": UrlToCheck}, f, ensure_ascii=False, indent=4)
        return jsonify({"url": UrlToCheck, "status": "valid"})
    
    else:
        return jsonify({"error": "URL invalide"}), 400

if __name__ == "__main__":
    app.run(debug=True)