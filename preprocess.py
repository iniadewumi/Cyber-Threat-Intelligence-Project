
import re
import pandas as pd
import pathlib
import matplotlib.pyplot as plt
from tld import get_tld, is_tld
import string
from ip_re import ip_re, short_re
from urllib.parse import urlparse
from io import StringIO
import requests
import category_encoders as ce


pd.options.display.max_columns = 100

ROOT = pathlib.Path().resolve()
DATA = ROOT / 'Data'
CSV = DATA / 'CSVs'
MALIC = CSV / 'Malicious Datasets'

# https://www.icdsoft.com/blog/what-are-the-most-popular-tlds-domain-extensions/
#TOP LEVEL DOMAINS BADNESS INDEX

class Preprocessor:
    def __init__(self):
        self.df = pd.read_csv(MALIC/'malicious_phish.csv')
        self.df = self.df[self.df.type != 'label']
        self.type_map = {'type_1': 'phishing', 'type_2': 'benign', 'type_3':'defacement', 'type_4':'malware'}
        print(f"\nMissing Data Check:\n{self.df.isnull().sum()}")
        print(f'\n\nDataset desription \n{self.df.describe()}')
        types = self.df['type'].value_counts()
        
        plt.bar(types.index, height=types, color=['navy',  'blue', 'purple', 'red'])


    def target_encode(self, var, target):
        print(f"Target Encoding {var}...")
        encoder = ce.OneHotEncoder()
        enc_target = encoder.fit_transform(self.df[target])
        enc_target.rename(columns=self.type_map, inplace=True)
        
        for targ in enc_target.columns:
            enc = ce.TargetEncoder()
            enc.fit(self.df[var], enc_target[targ])
            
            temp = enc.transform(self.df[var])
            temp.columns = [f'enc_{var}' for x in temp.columns]
            X = pd.concat([self.df[var], temp], axis=1)
        self.df = pd.concat([self.df, X], axis=1)
        self.df.drop(var, axis=1, inplace=True)


    # get_tld(x, as_object = True, fail_silently=False,fix_protocol=True)
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
    def get_scheme(self):
        self.df['scheme'] = self.df['url'].apply(lambda x: urlparse(x).scheme)
        
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

        desc = self.df.describe().T['mean']
        new_cols = ['url', 'type', 'scheme', 'domain', 'path', 'normal', 'digits', 'letters', "contains_ip", "is_shortened", 'tld_normal'] + list(desc[desc >0.01].index )
        self.df = self.df[new_cols]
        
        self.target_encode('tld_normal', 'type')
        self.target_encode('scheme', 'type')
        self.save_df()
        
    def save_df(self):
        self.df.to_csv(MALIC/'processed_dataframe.csv', index=False)
        self.df.to_csv(MALIC/'processed_dataframe.csv.zip', index=False, compression="zip")
        

if __name__ == '__main__':
    prep = Preprocessor()
    prep.workflow()
    print("\n\nSuccessfully Completed preprocessing!\nReady for training\n\n")
    
"""
What is the definition of Monte Carlo Simulation?
What are the parameters and plausible range of different random number generators (distributions)?
What is the difference between normal, truncated normal, and triangular distribution?
How do we simulate random numbers from empirical discrete distributions?
How does sample()function in R work? What are the inputs and outputs?
Difference between sampling with and without replacement in a simulation?
What are the properties of pseudo-random numbers?
What does the term such as IID and stationary mean?
How are the coding elements of the newsvendor model designed? What is the decision variable? How to find optimal? What are the size and dimensions of each object?
How do we determine that a distribution is a good fit for observed data? How do we compare different options? What test do we apply? What plots do we use?
How does bootstrapping work? What is the sample size in each iteration? How does replicate function work? How to measure confidence interval?
How does LCG work? Can you do it by hand?
How do we measure risk by Monte Carlo Simulation?
How does inverse transformation work for generating random variates? What are its parameters and other inputs? How it can be implemented in R?
How to simulate based on the output of input analysis?

"""