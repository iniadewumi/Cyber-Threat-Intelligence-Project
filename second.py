# url = "https://www.virustotal.com/gui/url/b590e7b5aee3a3584413b7c6faa54d9b852cd78cd2a2b9a7945bf02dc0db62d8"

import requests
import pandas as pd
import pathlib
import requests, json
from datetime import datetime



ROOT = pathlib.Path().resolve()
DATA = ROOT / 'Data'
CSV = DATA / 'CSVs'
DAILY_MALWARE = CSV / 'Malware Datasets' /'DAILY'


##https://labs.inquest.net/iocdb
#ioc  = Indicator of compromise
#repdb = Reputation Databases for
#dfi = Deep File Inspection


class MalwareCollector:
    def __init__(self):
        self.today = datetime.now().strftime('%d-%b-%y')
        self.urls = {"repdb": "https://labs.inquest.net/api/repdb/list", "dfi": "https://labs.inquest.net/api/dfi/list", "ioc":"https://labs.inquest.net/api/iocdb/list"}

    def retriever(self, command):    
        url= self.urls[command]
        self.response = requests.request("GET", url)
        
        if self.response.status_code !=200:
            raise ConnectionError(f"\nFailed to get data\nStatus code {self.response.status_code}")
            
        text_data = json.loads(self.response.text)

        return pd.DataFrame().from_dict(text_data['data'])
        
    def loop(self):
        for key in self.urls:
            filename  = DAILY_MALWARE/f'{key} ({self.today}).csv'
            if filename not in DAILY_MALWARE.iterdir():
                df = self.retriever(key)
                df.to_csv(filename, index=False)
                print(f"Downloaded and saved file {filename.name}")
            print(f"File {filename.name} already exists!")


if __name__ == '__main__':
    malcol = MalwareCollector()
    malcol.loop()