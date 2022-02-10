black_keyword_list = ['gov']

file_extend_list = ['png', 'jpg', 'gif', 'jpeg', 'ico', 'svg', 'bmp', 'mp3', 'mp4', 'avi', 'mpeg', 'mpg',
                                  'mov', 'zip', 'rar', 'tar', 'gz', 'mpeg', 'mkv', 'rmvb', 'iso', 'css', 'txt', 'ppt',
                                  'dmg', 'app', 'exe', 'pem', 'doc', 'docx', 'pkg', 'pdf', 'xml', 'eml''ini', 'so',
                                  'vbs', 'json', 'webp', 'woff', 'ttf', 'otf', 'log', 'image', 'map', 'woff2', 'mem',
                                  'wasm', 'pexe', 'nmf']

black_filename_list = ['jquery', 'bootstrap', 'react', 'vue', 'google-analytics']

link_pattern = r"""
            (?:"|')                               # Start newline delimiter
            (
                ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
                [^"'/]{1,}\.                        # Match a domainname (any character + dot)
                [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
                |
                ((?:/|\.\./|\./)                    # Start with /,../,./
                [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
                [^"'><,;|()]{1,})                   # Rest of the characters can't be
                |
                ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
                [a-zA-Z0-9_\-/]{1,}                 # Resource name
                \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
                (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
                |
                ([a-zA-Z0-9_\-]{1,}                 # filename
                \.(?:php|asp|aspx|jsp|json|
                    action|html|js|txt|xml)             # . + extension
                (?:\?[^"|']{0,}|))                  # ? mark with parameters
            )
            (?:"|')                               # End newline delimiter
		"""

js_pattern = 'src=["\'](.*?)["\']'
href_pattern = 'href=["\'](.*?)["\']'

leak_info_patterns = {'mail': r'([-_a-zA-Z0-9\.]{1,64}@%s)', 'author': '@author[: ]+(.*?) ',
                                   'accesskey_id': 'accesskeyid.*?["\'](.*?)["\']',
                                   'accesskey_secret': 'accesskeyid.*?["\'](.*?)["\']',
                                   'access_key': 'access_key.*?["\'](.*?)["\']', 'google_api': r'AIza[0-9A-Za-z-_]{35}',
                                   'google_captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
                                   'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
                                   'amazon_aws_access_key_id': r'AKIA[0-9A-Z]{16}',
                                   'amazon_mws_auth_toke': r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                                   'amazon_aws_url': r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
                                   'amazon_aws_url2': r"("r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com"r"|s3://[a-zA-Z0-9-\.\_]+"r"|s3-[a-zA-Z0-9-\.\_\/]+"r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+"r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
                                   'facebook_access_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
                                   'authorization_basic': r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
                                   'authorization_bearer': r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
                                   'authorization_api': r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
                                   'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
                                   'twilio_api_key': r'SK[0-9a-fA-F]{32}',
                                   'twilio_account_sid': r'AC[a-zA-Z0-9_\-]{32}',
                                   'twilio_app_sid': r'AP[a-zA-Z0-9_\-]{32}',
                                   'paypal_braintree_access_token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
                                   'square_oauth_secret': r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
                                   'square_access_token': r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
                                   'stripe_standard_api': r'sk_live_[0-9a-zA-Z]{24}',
                                   'stripe_restricted_api': r'rk_live_[0-9a-zA-Z]{24}',
                                   'github_access_token': r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
                                   'rsa_private_key': r'-----BEGIN RSA PRIVATE KEY-----',
                                   'ssh_dsa_private_key': r'-----BEGIN DSA PRIVATE KEY-----',
                                   'ssh_dc_private_key': r'-----BEGIN EC PRIVATE KEY-----',
                                   'pgp_private_block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
                                   'json_web_token': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
                                   'slack_token': r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
                                   'SSH_privKey': r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
                                   'possible_Creds': r"(?i)("r"password\s*[`=:\"]+\s*[^\s]+|"r"password is\s*[`=:\"]*\s*[^\s]+|"r"pwd\s*[`=:\"]*\s*[^\s]+|"r"passwd\s*[`=:\"]+\s*[^\s]+)", }