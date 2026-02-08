from urllib.parse import urlparse, urlencode, quote, unquote
import tldextract
import model
import googleVerify
import cscore
global BASE_SCORE
BASE_SCORE = 50  # default trust_ score of url out of 100


def main(url):

    try:

        # input validattion
        url = model.include_protocol(url)
        url_validation = model.validate_url(url)

        # default data
        domain = tldextract.extract(url).domain + '.' + tldextract.extract(url).suffix
        response = {'status': 'SUCCESS', 'url': url}
        trust_score = BASE_SCORE


        # ================== starting url assessment ==================

        # phishtank check
        phishtank_response = model.phishtank_search(url)
        if phishtank_response:
            response['msg'] = "This is a verified phishing link."


        # website status
        response['response_status'] = url_validation


        # domain_rank
        domain_rank = model.get_domain_rank(domain)
        trust_score = model.calculate_trust_score(trust_score, 'domain_rank', domain_rank)
        if domain_rank:
            response['rank'] = domain_rank
        else:
            response['rank'] = '10,00,000+'


        # domain_age and whois_data
        whois_data = model.whois_data(domain)
        trust_score = model.calculate_trust_score(trust_score, 'domain_age', whois_data['age'])
        if whois_data['age'] == 'Not Given':
            response['age'] = whois_data['age']
        else:
            response['age'] = str(round(whois_data['age'],1)) + ' year(s)'
        response['whois'] = whois_data['data']


        # is_url_shortened
        is_url_shortened = model.is_url_shortened(url)
        trust_score = model.calculate_trust_score(trust_score, 'is_url_shortened', is_url_shortened)
        response['is_url_shortened'] = is_url_shortened


        # hsts_support
        hsts_support = model.hsts_support(url)
        trust_score = model.calculate_trust_score(trust_score, 'hsts_support', hsts_support)
        response['hsts_support'] = hsts_support


        # ip_present
        ip_present = model.ip_present(url)
        trust_score = model.calculate_trust_score(trust_score, 'ip_present', ip_present)
        response['ip_present'] = ip_present


        # url_redirects
        url_redirects = model.url_redirects(url)
        trust_score = model.calculate_trust_score(trust_score, 'url_redirects', url_redirects)
        response['url_redirects'] = url_redirects


        # too_long_url
        too_long_url = model.too_long_url(url)
        trust_score = model.calculate_trust_score(trust_score, 'too_long_url', too_long_url)
        response['too_long_url'] = too_long_url


        # too_deep_url
        too_deep_url = model.too_deep_url(url)
        trust_score = model.calculate_trust_score(trust_score, 'too_deep_url', too_deep_url)
        response['too_deep_url'] = too_deep_url

        
        # get ip address
        ip = model.get_ip(domain)
        if ip == 0:
            response['ip'] = 'Unavailable'
        else:
            response['ip'] = ip

        
        # get_certificate_details
        ssl = model.get_certificate_details(domain)
        response['ssl'] = ssl


        trust_score = int(max(min(trust_score, 100), 0))
        response['trust_score']= trust_score

        # ================== starting Model try and catching ================== #
        model_score = int(model.find_model_score(url))
        response['model_score'] = model_score

        #==================== add google api verify section here ============================= #
                # Google Safe Browsing API verification
        google_verification_result = googleVerify.google_verification(url)
        if google_verification_result:
            response['google_verified'] = google_verification_result['google_verified']
            response['threat_type'] = google_verification_result['threat_type']
            response['platform_type'] = google_verification_result['platform_type']
            response['threat_entry_type'] = google_verification_result['threat_entry_type']
        else:
            response['google_verified'] = 'error'
            response['threat_type'] = None
            response['platform_type'] = None
            response['threat_entry_type'] = None

        #==================== google api verify section ends here ============================= #
         
        # ================== starting combine .py ===============================#
        final_verdict = cscore.is_phishing(trust_score,model_score)
        if google_verification_result == "yes":
            final_verdict = True
        response['final_verdict'] = final_verdict

        return response

# ----------------------------------------------------------------------------------
    except Exception as e:
        print(f"Error: {e}")
        response = {'status': 'ERROR', 'url': url, 'msg': "Some error occurred, please check the URL."}
        return response