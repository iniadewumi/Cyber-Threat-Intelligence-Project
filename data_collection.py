
import requests, json
import zipfile
import pandas as pd
import pathlib
from kaggle.api.kaggle_api_extended import KaggleApi
from datetime import datetime
from io import StringIO

ROOT = pathlib.Path().resolve()
DATA = ROOT / 'Data'
AUTH = ROOT / 'kaggle.json'
CSV = DATA / 'CSVs'
ZIPS = DATA / 'Zip'
MALIC = CSV / 'Malicious Datasets'
MALW = CSV / 'Malware Datasets'
DAILY_MALWARE = MALW /'DAILY'

class Downloader:
    def __init__(self):
        self.api = KaggleApi()
        self.api.authenticate()
        self.zip_file = ZIPS/'cti-project.zip'
        self.today = datetime.now().strftime('%d-%b-%y')
        self.urls = {"repdb": "https://labs.inquest.net/api/repdb/list", "dfi": "https://labs.inquest.net/api/dfi/list", "ioc":"https://labs.inquest.net/api/iocdb/list"}
        MALIC.mkdir(parents=True, exist_ok=True)
        DAILY_MALWARE.mkdir(parents=True, exist_ok=True)
        ZIPS.mkdir(parents=True, exist_ok=True)
        
    def get_malware_dataset(self, command):
        url= self.urls[command]
        response = requests.request("GET", url)
        
        if response.status_code !=200:
            raise ConnectionError(f"\nFailed to get data\nStatus code {response.status_code}")
            
        text_data = json.loads(response.text)

        return pd.DataFrame().from_dict(text_data['data'])
                

    
    def checker(self, file=None, silent=False):
        if not file:
            file = self.zip_file

        if file.exists() and file.stat().st_size>16:
            print(None if silent else "Zip file found! Extract data from zip file")
            return True
        return False
    
    def get_malicious_dataset(self):
        if not self.checker(self.zip_file, silent=True):  
            self.api.dataset_download_files('olasubomiiniadewumi/cti-project/malicious_phish.csv', path=ZIPS)
            print(f"Downloaded zip file to ./{'/'.join(self.zip_file.parts[-3:])}")  
        return self.checker()
    
    def unzip(self, from_path, to_path):
        print(f"Unzipping file at ./{'/'.join(from_path.parts[-3:])}")
        with zipfile.ZipFile(from_path, 'r') as f:
            f.extractall(to_path)
        return print(f"Extracted zip content to ./{'/'.join(from_path.parts[-3:])}")

    def extract_git_data(self):
        resp = requests.get('https://raw.githubusercontent.com/faizann24/Using-machine-learning-to-detect-malicious-URLs/master/data/data.csv')
        other = pd.read_csv(StringIO(resp.text), names=['url', 'type'])
        other.type.replace({"bad":"malware", "good":"benign"}, inplace=True)

        resp2 = requests.get('https://raw.githubusercontent.com/faizann24/Using-machine-learning-to-detect-malicious-URLs/master/data/data2.csv')
        other2 = pd.read_csv(StringIO(resp2.text), names=['url', 'type'])
        other2.type.replace({"bad":"malware", "good":"benign"}, inplace=True)
        self.df = pd.concat([self.df, other, other2])  
        self.df.drop_duplicates('url', inplace=True)
        
    def download(self):
        for key in self.urls:
            filename  = DAILY_MALWARE/f'{key} ({self.today}).csv'
            if filename not in DAILY_MALWARE.iterdir():
                df = self.get_malware_dataset(key)
                df.to_csv(filename, index=False)               
                print(f"Downloaded and saved file {filename.name}")
                continue
            print(f"File {filename.name} already exists!")

            
        if self.get_malicious_dataset():
            self.unzip(self.zip_file, MALIC)
        print("\n\nExtracting Git Data...")
        self.df = pd.read_csv(MALIC/'malicious_phish.csv')
        self.extract_git_data()
        print("Success, GIT data joined to DF")
        self.df.to_csv(MALIC/'malicious_phish.csv', index=False)
    
        print("\n\nSuccessfully downloaded and extracted data")
if __name__ == '__main__':
    m = Downloader()
    m.download()
    # input("Press ENTER to exit...")


# url = "https://www.virustotal.com/gui/url/b590e7b5aee3a3584413b7c6faa54d9b852cd78cd2a2b9a7945bf02dc0db62d8"

##https://labs.inquest.net/iocdb
#ioc  = Indicator of compromise
#repdb = Reputation Databases for
#dfi = Deep File Inspection
