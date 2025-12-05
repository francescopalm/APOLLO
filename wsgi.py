from flask import Flask, request, jsonify
from email.message import EmailMessage
from email.generator import Generator
import base64
import main
import os
import config

app = Flask(__name__)

# CORS Policy
# 
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "chrome-extension://agmlpgjhbgcfcnnfifoklphcohcaidop"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json

    # Decoding the RAW string (in base64URL) received from the background script
    dataDecoded = base64.urlsafe_b64decode(data)

    # Create the .eml file to be provided as input to APOLLO
    build_eml(dataDecoded)


    result, warning_msg = main.main()

    # Adds the explanation to the Python dictionary 'result'
    result["warning_msg"] = warning_msg
    return jsonify(result), 200


@app.route('/setapikey', methods=['POST'])
def set_api_key():
    data = request.json

    # Save the received API KEYs in 'config.json'
    config.save_config(data)

    return jsonify({"success": True, "message": "config.json updated."}), 200


# Create .eml file
def build_eml(rawData) -> str:

    # Use current filepath directory
    filepath = os.getcwd()

    # Save e-mail
    with open(filepath+"/current.eml", 'wb') as f:
        f.write(rawData)

    return filepath


if __name__ == "__main__":
    app.run(debug=True)