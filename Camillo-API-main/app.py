from flask import Flask, request, jsonify
import controller
import base64
from flask_cors import CORS
import os
import colorama
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
def clear_screen():
  # Using os.system to execute clear command
  os.system('clear' if os.name == 'posix' else 'cls')


def banner(api_url):
    banner_text = ''' 
   ______                _ ____               ___    ____  ____
  / ____/___ _____ ___  (_) / /___           /   |  / __ \/  _/
 / /   / __ `/ __ `__ \/ / / / __ \______   / /| | / /_/ // /  
/ /___/ /_/ / / / / / / / / / /_/ /_____/  / ___ |/ ____// /   
\____/\__,_/_/ /_/ /_/_/_/_/\____/        /_/  |_/_/   /___/ 

================= 0xT3sla & Randomehomie ====================
'''
    clear_screen()
    print(banner_text)
    print(colorama.Fore.GREEN + "App is running!" + colorama.Style.RESET_ALL)
    print("Send POST requests to: " + colorama.Fore.BLUE + f"{api_url}"+ colorama.Style.RESET_ALL)


@app.route('/api/analyze-url', methods=['POST'])
def analyze_url():
    try:
        # Get the JSON data from the request
        data = request.json
        
        # Decode the base64 URL
        encoded_url = data.get('url', '')
        url = base64.urlsafe_b64decode(encoded_url).decode('utf-8')
        
        # Call the main function to analyze the URL
        result = controller.main(url)
        
        # Return the response as JSON
        return jsonify(result)
    except Exception as e:
        # Return error message if any exception occurs
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    host = "0.0.0.0"
    port = 6969
    api_url = f"http://localhost:{port}/api/analyze-url"
    banner(api_url)
    app.run(host=host,port=port,debug=True)