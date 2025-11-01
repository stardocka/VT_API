"""
Copyright 2025 URL Analyzer Project

This file is part of URL Analyzer project
Author : Antoine Puteanus-Mautino

Last update : November 01, 2025
"""

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
        VirusTotalResponse = ContactVirusTotalApi(UrlToCheck)

        if VirusTotalResponse == None:
            return jsonify({"url": UrlToCheck, "error": "VirusTotal API error"}), 500
        
        AnalysisReportURL = VirusTotalResponse["data"]["links"]["self"]
        FullAnalysisData = GetAnalysisReport(AnalysisReportURL)

        # We only take the keys we need
        if FullAnalysisData and "data" in FullAnalysisData:
            stats = FullAnalysisData["data"]["attributes"]["stats"]
            response_data = {
                "url": UrlToCheck,
                "malicious_votes": stats.get("malicious", 0),
                "harmless_votes": stats.get("harmless", 0)
            }
        else:
            response_data = {
                "url": UrlToCheck,
                "error": "Impossible de récupérer les stats"
            }

        return jsonify(response_data)

    
    else:
        return jsonify({"error": "URL invalide"}), 400
    

def ContactVirusTotalApi(UserUrl):
    VirusTotalApiUrl = "https://www.virustotal.com/api/v3/urls"

    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY,
    }

    data = {"url": UserUrl}
    response = requests.post(VirusTotalApiUrl, headers=headers, data=data)

    if response.status_code == 200 or response.status_code == 201:
        return response.json()
    else:
        print("Error")
        return None
    

def GetAnalysisReport(AnalysisReportURL):
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY,
    }

    response = requests.get(AnalysisReportURL, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print("Error, none analysis found")
        return None


if __name__ == "__main__":
    app.run(debug=True)