
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

ROOT = pathlib.Path().resolve()
DATA = ROOT / 'Data'
CSV = DATA / 'CSVs'
MALIC = CSV / 'Malicious Datasets'



class Preprocessor:
    def __init__(self):
        self.df = pd.read_csv(MALIC/'malicious_phish.csv')
        self.df = self.df[self.df.type != 'label']
        print(f"\nMissing Data Check:\n{self.df.isnull().sum()}")
        print(f'\n\nDataset desription \n{self.df.describe()}')
        types = self.df['type'].value_counts()
        plt.bar(types.index, height=types, color=['navy',  'blue', 'purple', 'red'])



    # get_tld(x, as_object = True, fail_silently=False,fix_protocol=True)
    def extract_domain(self, url):
        try:
            res = get_tld(url, as_object = True, fail_silently=False,fix_protocol=True)
            domain = res.parsed_url.netloc
            scheme = res.parsed_url.scheme
            path =   res.parsed_url.path
            normal = 0 if re.search(str(urlparse(url).hostname), url) else 1

        except Exception:
            domain = None
            scheme = url.split(":")[0] if len(url.split(":")[0])>1 else ""
            path = None
            normal = 1
        digits = len(re.findall('[0-9]+', url))
        letters = len(re.findall('[A-Za-z]', url))
        contains_ip = ip_re(url)
        is_shortened = short_re(url)

        return [scheme, domain, path, normal, digits, letters, contains_ip, is_shortened]
    def workflow(self):
        print("\n\nRemoving www...")
        self.df['url'] = self.df['url'].str.replace('www.', '', regex=True)

        print("Calculating link length...")
        self.df['url_length'] = self.df['url'].apply(lambda x: len(str(x)))

        print("Extracting URL components...")
        self.df[['scheme', 'domain', 'path', "normal", "digits", "letters", "contains_ip", "is_shortened"]] = self.df['url'].apply(lambda url: self.extract_domain(url)).tolist()

        print("Finding secure links...")
        self.df['secure'] = self.df['scheme'].apply(lambda x: 1 if x=='https' else 0)

        print("Finding and counting special characters")
        for c in list(string.punctuation)+["//"]:
            self.df[c] = self.df['url'].apply(lambda i: i.count(c))

        desc = self.df.describe().T['mean']
        new_cols = ['url', 'type', 'scheme', 'domain', 'path', 'normal', 'digits', 'letters', "contains_ip", "is_shortened"] + list(desc[desc >0.01].index )
        self.df = self.df[new_cols]
        self.save_df()
        
    def save_df(self):
        self.df.to_csv(MALIC/'processed_dataframe.csv', index=False)
        self.df.to_csv(MALIC/'processed_dataframe.csv.zip', index=False, compression="zip")
        

if __name__ == '__main__':
    prep = Preprocessor()
    prep.workflow()
    print("\n\nSuccessfully Completed preprocessing!\nReady for training\n\n")
