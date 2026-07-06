from urllib.parse import urlparse, urlencode, quote, unquote
import tldextract
import model
import googleVerify
import cscore
global BASE_SCORE
BASE_SCORE = 50  # default trust_ score of url out of 100

def main(url):

    try:
        # input validation
        url = model.include_protocol(url)
        
        # unified fetch of url metadata to reduce duplicate HTTP requests
        url_metadata = model.fetch_url_metadata(url)
        url_validation = model.validate_url(url_metadata)

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

        # open source blocklists check (StevenBlack adware/malware hosts list)
        in_blocklist = model.check_blocklist(domain)
        if in_blocklist:
            trust_score = max(0, trust_score - 60)
        response['in_blocklist'] = in_blocklist

        # EasyList adware and trackers check
        is_adware_tracker = model.check_easylist(domain)
        if is_adware_tracker:
            trust_score = max(0, trust_score - 15)
        response['is_adware_tracker'] = is_adware_tracker

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
        hsts_support = model.hsts_support(url_metadata)
        trust_score = model.calculate_trust_score(trust_score, 'hsts_support', hsts_support)
        response['hsts_support'] = hsts_support

        # ip_present
        ip_present = model.ip_present(url)
        trust_score = model.calculate_trust_score(trust_score, 'ip_present', ip_present)
        response['ip_present'] = ip_present

        # url_redirects
        url_redirects = model.url_redirects(url_metadata)
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

        # content_check
        content_res = model.content_check(url_metadata)
        trust_score = model.calculate_trust_score(trust_score, 'content', content_res)
        response['content_check'] = content_res
        
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
        response['trust_score'] = trust_score

        # ================== starting Model try and catching ================== #
        model_score = int(model.find_model_score(url))
        response['model_score'] = model_score

        # ==================== Google verification ============================= #
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

        # ================== final verdict calculation =============================== #
        final_verdict = cscore.is_phishing(trust_score, model_score)
        if google_verification_result and google_verification_result.get('google_verified') == "yes":
            final_verdict = True
        response['final_verdict'] = final_verdict

        # ================== Heuristic Threat Breakdown ============================= #
        breakdown = []
        
        # 1. Global rank check
        if domain_rank == 0 or domain_rank > 1000000:
            breakdown.append({
                "title": "Global Popularity",
                "desc": "Domain is not in the top 1 million websites list. This is highly common for new or phishing domains.",
                "severity": "warning"
            })
        elif domain_rank > 500000:
            breakdown.append({
                "title": "Global Popularity",
                "desc": f"Domain popularity rank is relatively low (#{domain_rank:,} globally).",
                "severity": "info"
            })
        else:
            breakdown.append({
                "title": "Global Popularity",
                "desc": f"Domain is highly trusted and ranked #{domain_rank:,} globally.",
                "severity": "safe"
            })

        # 2. Domain age check
        if whois_data and whois_data['age'] != 'Not Given':
            age_yrs = whois_data['age']
            if age_yrs < 1.0:
                breakdown.append({
                    "title": "Domain Age",
                    "desc": f"Domain was registered very recently ({round(age_yrs, 2)} years ago), typical of temporary scams.",
                    "severity": "danger"
                })
            elif age_yrs < 5.0:
                breakdown.append({
                    "title": "Domain Age",
                    "desc": f"Domain is relatively young ({round(age_yrs, 2)} years old).",
                    "severity": "warning"
                })
            else:
                breakdown.append({
                    "title": "Domain Age",
                    "desc": f"Domain is established and has been registered for {round(age_yrs, 1)} years.",
                    "severity": "safe"
                })
        else:
            breakdown.append({
                "title": "Domain Age",
                "desc": "No registration age records found. This indicates the registrar has hidden this details or domain is private.",
                "severity": "warning"
            })

        # 3. URL shortener check
        if is_url_shortened:
            breakdown.append({
                "title": "URL Shortener",
                "desc": "URL uses a shortening service which hides the real target destination.",
                "severity": "danger"
            })

        # 4. IP usage check
        if ip_present:
            breakdown.append({
                "title": "IP Address Usage",
                "desc": "URL references a raw IP address directly instead of a domain name.",
                "severity": "danger"
            })

        # 5. Redirects check
        if len(url_redirects) > 0:
            breakdown.append({
                "title": "Redirection Loops",
                "desc": f"URL redirected {len(url_redirects)} times before reaching the final page.",
                "severity": "warning"
            })

        # 6. HSTS check
        if hsts_support == 1:
            breakdown.append({
                "title": "HSTS Security",
                "desc": "Strict Transport Security (HSTS) is enabled, enforcing secure SSL connections.",
                "severity": "safe"
            })
        else:
            breakdown.append({
                "title": "HSTS Security",
                "desc": "Strict Transport Security (HSTS) is not enabled, potentially exposing credentials.",
                "severity": "warning"
            })

        # 7. URL length and depth checks
        if too_long_url:
            breakdown.append({
                "title": "URL Length",
                "desc": f"URL is unusually long ({len(url)} characters) which is often used to hide the domain name.",
                "severity": "warning"
            })
        if too_deep_url:
            breakdown.append({
                "title": "URL Path Depth",
                "desc": "URL contains deep folder structures, often used to mimic trusted directory paths.",
                "severity": "warning"
            })

        # 8. Content analysis checks
        if isinstance(content_res, dict):
            if content_res.get('onmouseover') == 1:
                breakdown.append({
                    "title": "Script Link Spoofing",
                    "desc": "Page modifies the browser status bar links dynamically on hover.",
                    "severity": "danger"
                })
            if content_res.get('right-click') == 1:
                breakdown.append({
                    "title": "Right-click Blocked",
                    "desc": "Webpage blocks right-clicks to prevent viewing the HTML source code.",
                    "severity": "warning"
                })
            if content_res.get('iframe') == 1:
                breakdown.append({
                    "title": "Embedded iframe",
                    "desc": "Webpage embeds external iframe elements, commonly used to hide foreign forms.",
                    "severity": "info"
                })
            if content_res.get('login') == 1:
                breakdown.append({
                    "title": "Credential Request",
                    "desc": "Webpage contains login/password keywords, indicating it requests credentials.",
                    "severity": "warning" if trust_score < 75 else "info"
                })

        # 9. Google Safe Browsing threat match
        if response.get('google_verified') == "yes":
            breakdown.append({
                "title": "Google Safe Browsing",
                "desc": f"Google Safe Browsing explicitly flags this URL as dangerous! Threat type: {response.get('threat_type')}.",
                "severity": "danger"
            })

        # 10. Open Source Blocklist matches
        if in_blocklist:
            breakdown.append({
                "title": "Open Source Blocklist Match",
                "desc": "Domain matches known malicious lists, adware hosts, or phishing tracking databases.",
                "severity": "danger"
            })

        # 11. EasyList adware/tracker matches
        if is_adware_tracker:
            breakdown.append({
                "title": "Adware & Tracker (EasyList)",
                "desc": "Domain matches public EasyList filters, indicating it hosts ads, analytical tracking scripts, or adware packages.",
                "severity": "warning"
            })

        response['breakdown'] = breakdown
        return response

    except Exception as e:
        print(f"Error: {e}")
        response = {'status': 'ERROR', 'url': url, 'msg': "Some error occurred, please check the URL."}
        return response
