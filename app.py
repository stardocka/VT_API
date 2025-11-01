from flask import Flask, request, jsonify
from dotenv import load_dotenv
import os, requests, json, re, base64

load_dotenv("ini.env")
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

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

        print(jsonify({"url": UrlToCheck, "status": "valid"}))
        VirusTotalResponse = ContactVirusTotalApi()

        if VirusTotalResponse == None:
            return jsonify({"url": UrlToCheck, "error": "VirusTotal API error"}), 500
        
        return jsonify({"url": UrlToCheck, "vt_result": VirusTotalResponse})
    
    else:
        return jsonify({"error": "URL invalide"}), 400
    

def ContactVirusTotalApi(UserUrl="https://google.com"):
    VirusTotalApiUrl = "https://www.virustotal.com/api/v3/urls"

    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

    # VirusTotal wants to get either a base64 encoding or SHA256 + cancanonicalization
    # https://docs.virustotal.com/reference/url to know the right format
    # Option chosen: base64

    EncodedUrl = UserUrl.encode()
    Base64Url = base64.urlsafe_b64encode(EncodedUrl).decode().strip("=")

    data = {"url": UserUrl}

    response = requests.post(VirusTotalApiUrl, headers=headers, data=data)

    # AJOUT: afficher le JSON complet pour debug
    print(response.json())

    res_json = response.json()

    if response.status_code == 200 or response.status_code == 201:
        return response.json()
    else:
        print("Error")
        return None


if __name__ == "__main__":
    app.run(debug=True)