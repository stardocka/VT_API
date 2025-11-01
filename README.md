AIRBUS - JR10353765 - Technical Challenge
Intern Exercise: URL Analyzer
Antoine Puteanus-Mautino

Introduction:

The primary objective of this project is to deploy an API that allows us to determine whether a link is malicious or not.

To do this, our API can be accessed via a POST request to the Python Flask server.

The API is based on the VirusTotal API and will return three pieces of information:
- harmless votes
- malicious votes
- requested URL

How to use:

To setup the environment you need:

- Clone the project from the GitHub repository:
    https://github.com/stardocka/VT_API

    run the following commands: 
        git clone https://github.com/stardocka/VT_API
        cd VT_API
    
    /!\ Make sure you have first installed Git

- Create a virtual environmment (not mandatory and can avoid conflicts with other projects)

    python -m venv venv
    venv\Scripts\activate

- Make the installations

    Make sure to have first installed pip and python

    run the following command:
        pip install -r requirements.txt

- Add the ini.env file

    This file contain your own API Virus Total key. To find this key, connect to your VirusTotal account, in your profile you will see "API key"
    The ini.env file must contain this line:
    VIRUSTOTAL_API_KEY= Your key here

- Run the Flask Server

    To run the Flask Server, you only have to run this command: flask run
    It should be running locally with the port number 5000 as follow: http://127.0.0.1:5000

- Open a cmd terminal:

    You can run the following curl command:
    curl -X POST http://127.0.0.1:5000/analyze -H "Content-Type: application/json" -d "{\"url\":\"http://example.com\"}"

    User inputs have been filtered since a user can inject malicious code. This can be tested with the following command:
    curl -X POST http://127.0.0.1:5000/analyze -H "Content-Type: application/json" -d "{\"url\":\"print('HelloWorld')\"}"

To go further:

    We could think to implement a user interface to make interactions easier and a system to enter several links to automate for a huge amout of links.


Link to the documentation: 
 - https://docs.virustotal.com/reference/overview
 - https://docs.virustotal.com/reference/url
 - https://docs.virustotal.com/reference/scan-url
 - https://docs.virustotal.com/reference/url-info
 - https://docs.virustotal.com/reference/urls-analyse
 - https://docs.virustotal.com/reference/urls-votes-get

 Link to the ressource used to test the REGEX:
 - https://regex101.com/