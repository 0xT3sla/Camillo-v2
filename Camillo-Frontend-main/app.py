from flask import Flask, request, render_template, jsonify, redirect, url_for
import requests
import base64
from bs4 import BeautifulSoup
import urllib.parse
from urllib.parse import urljoin
import json
import html
from functools import wraps

app = Flask(__name__)

def mobile_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_agent = request.user_agent.string
        if 'mobile' in user_agent.lower():
            return f(*args, **kwargs)
        else:
            return redirect('/')
    return decorated_function

@app.before_request
def check_mobile():
    if request.path.startswith('/mobile'):
        user_agent = request.user_agent.string
        if 'mobile' not in user_agent.lower():
            return redirect('/')
    elif 'mobile' in request.user_agent.string.lower():
        if not request.path.startswith('/static'):
            return redirect('/mobile')

API_URL = "http://127.0.0.1:6969/api/analyze-url"

@app.route('/',  methods=['GET','POST'])
def home():
    try:
        if request.method == 'POST' and 'url' in request.form:
            url = request.form['url'].strip()
            # Encode URL to base64
            encoded_url = base64.urlsafe_b64encode(url.encode('utf-8')).decode('utf-8')
            # JSON data containing the encoded URL
            data = {'url': encoded_url}
            # Send POST request to the API endpoint
            response = requests.post(API_URL, json=data)
            if response.status_code == 200:
                # Convert JSON response to dictionary
                output = response.json()
                # Redirect to /verified route with details
                if output.get('google_verified') == 'yes':
                    return redirect(url_for('verified', 
                        google_verified=output.get('google_verified'),
                        platform_type=output.get('platform_type'),
                        threat_entry_type=output.get('threat_entry_type'),
                        threat_type=output.get('threat_type')))
                
            else:
                output = {'status': 'ERROR', 'msg': f"Failed to analyze URL: {response.status_code} - {response.text}"}
        else:
            output = 'NA'
    except Exception as e:
        output = {'status': 'ERROR', 'msg': str(e)}

    return render_template('index.html', output=output)


@app.route('/preview', methods=['POST'])
def preview():
    try:
        url = request.form.get('url')
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        # inject external resources into HTML
        for link in soup.find_all('link'):
            if link.get('href'):
                link['href'] = urljoin(url, link['href'])
        
        # Uncomment this if you want to enable script
        # for script in soup.find_all('script'):
        #     if script.get('src'):
        #         script['src'] = urljoin(url, script['src'])

        for img in soup.find_all('img'):
            if img.get('src'):
                img['src'] = urljoin(url, img['src'])

        return render_template('preview.html', content=soup.prettify())
    except Exception as e:
        return  f"Error: {e}"


@app.route('/source-code', methods=['GET','POST'])
def view_source_code():

    try:
        url = request.form.get('url')
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        formatted_html = soup.prettify()
        
        return render_template('source_code.html', formatted_html = formatted_html, url = url)
    
    except Exception as e:
        return  f"Error: {e}"

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/verified', methods=['GET', 'POST'])
def verified():
    google_verified = request.args.get('google_verified')
    platform_type = request.args.get('platform_type')
    threat_entry_type = request.args.get('threat_entry_type')
    threat_type = request.args.get('threat_type')
    verified_response = {
        "google_verified" : google_verified,
        "platform_type" : platform_type,
        "threat_entry_type" : threat_entry_type,
        "threat_type" : threat_type
    }

    return render_template('verified.html', verified_response=verified_response)

@app.route('/mobile')
@mobile_only
def mobile():
    return render_template('mobile.html')

if __name__ == '__main__':
    app.run(host= '0.0.0.0',debug=True)
