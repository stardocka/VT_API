from flask import Flask
import json, re

app = Flask(__name__)

@app.route('/')

def GetUrlToScan():
    # Get the input of the user
    UrlToCheck = str(input("Enter the URL to check:"))

    # Check the user's input with a regex
    RegexPatternHttps = "https?:\/\/[a-zA-Z0-9\-\.]+[a-zA-Z]{2,6}"
    RegexPatternHttp = "https?:\/\/[a-zA-Z0-9\-\.]+[a-zA-Z]{2,6}"

    # If the URL has been recognized then we can process to the analysis
    if re.match(RegexPatternHttps, UrlToCheck) or re.match(RegexPatternHttp, UrlToCheck):
        with open("ToCheck.json", 'w', encoding='utf-8') as f:
            json.dump({"url": UrlToCheck}, f, ensure_ascii=False, indent=4)
    
    else:
        print("Unrecognized URL")



GetUrlToScan()