
class Predictor:
    def __init__(self, url=None):
        url = "https://www.youtube.com/watch?v=3dx312O15fM"
        self.df = pd.DataFrame({"url":[url]})
        
    def extract_domain(self, url):
        try:
            res = get_tld(url, as_object = True, fail_silently=False,fix_protocol=True)
            domain = res.parsed_url.netloc
            scheme = res.parsed_url.scheme
            path =   len(res.parsed_url.path)
            normal = 0 if re.search(str(urlparse(url).hostname), url) else 1
            tld = res.tld
    
        except Exception:
            domain = None
            scheme = url.split(":")[0] if len(url.split(":")[0])<5 else ""
            path = 0
            normal = 1
            tld = ''
        digits = len(re.findall('[0-9]+', url))
        letters = len(re.findall('[A-Za-z]', url))
        contains_ip = ip_re(url)
        is_shortened = short_re(url)
        return [scheme, domain, path, normal, digits, letters, contains_ip, is_shortened, tld]
    
    def workflow(self):
        print("\n\nRemoving www...")
        self.df['url'] = self.df['url'].str.replace('www.', '', regex=True)

        print("Calculating link length...")
        self.df['url_length'] = self.df['url'].apply(lambda x: len(str(x)))

        print("Extracting URL components...")
        self.df[['scheme', 'domain', 'path', "normal", "digits", "letters", "contains_ip", "is_shortened", 'tld_normal']] = self.df['url'].apply(lambda url: self.extract_domain(url)).tolist()

        print("\nFinding secure links...")
        self.df['secure'] = self.df['scheme'].apply(lambda x: 1 if x=='https' else 0)

        print("Finding and counting special characters\n")
        for c in list(string.punctuation)+["//"]:
            self.df[c] = self.df['url'].apply(lambda i: i.count(c))

        # desc = self.df.describe().T['mean']
        # new_cols = ['url', 'scheme', 'domain', 'path', 'normal', 'digits', 'letters', "contains_ip", "is_shortened", 'tld_normal'] + list(desc[desc >0.01].index )
        # self.df = self.df[new_cols]
        import var_map
        self.df['enc_tld_normal'] = var_map.tld_map[self.df['tld_normal'][0]]
        self.df['enc_scheme'] = var_map.scheme_map[self.df['scheme'][0]]

        self.df = self.df[['path', 'normal', 'digits', 'letters', 'contains_ip', 'is_shortened','url_length', 'secure', '%', '&', "'", '+', '-', '.', '/', ':', ';', '=', '?', '\\', '_', '~', '//', 'enc_tld_normal', 'enc_scheme']]
        
        