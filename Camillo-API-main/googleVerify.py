import os
import requests
from dotenv import load_dotenv

load_dotenv()

def google_verification(url):
    try:
        api_key = os.getenv("API_KEY")  # Retrieve API key from environment variable
        api_url = os.getenv("API_URL")  # Retrieve API URL from environment variable
        
        if api_key is None or api_url is None:
            print("Google API key or URL not found in environment variables. Make sure to add them to your .env file.")
            return None
        
        # Construct the request body
        request_body = {
            "client": {
                "clientId": "camillo-api",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],  # Retrieve matches for all platforms
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        # Send POST request to the Google Safe Browsing API endpoint
        response = requests.post(f"{api_url}/threatMatches:find?key={api_key}", json=request_body)

        # Check if request was successful
        if response.status_code == 200:
            # Parse JSON response
            json_response = response.json()
            if 'matches' in json_response:
                # If matches are found, return detailed information
                match_info = json_response['matches'][0]
                google_verified = {
                    "google_verified": "yes",
                    "threat_type": match_info.get('threatType', None),
                    "platform_type": match_info.get('platformType', None),
                    "threat_entry_type": match_info.get('threatEntryType', None)
                }
                return google_verified
            else:
                # If no matches found, return None for other keys
                return {"google_verified": "no", "threat_type": None, "platform_type": None, "threat_entry_type": None}
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None
    except requests.RequestException as e:
        print(f"Error: {e}")
        return None