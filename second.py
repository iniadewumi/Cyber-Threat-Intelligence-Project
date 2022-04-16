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
                # df.drop_duplicates(inplace=True)
                df.to_csv(filename, index=False)
                print(f"Downloaded and saved file {filename.name}")
                continue
            
            print(f"File {filename.name} already exists!")
        self.merge()
    def merge(self):
        for key in self.urls:
            df = pd.read_csv(DAILY_MALWARE/f'{key} ({self.today}).csv')
            full_df = pd.read_csv(DAILY_MALWARE.parent / f'all_{key}.csv')
            full_df = pd.concat([df, full_df])
            full_df.drop_duplicates(inplace=True)
            print(f"Updated the compilation all_{key}")
            full_df.to_csv(DAILY_MALWARE.parent / f'all_{key}.csv', index=False)
    
    
    
if __name__ == '__main__':
    malcol = MalwareCollector()
    malcol.loop()
    


# for key in malcol.urls:
    
#     rep = pd.DataFrame(columns=['Column Name', 'Description', 'count', 'unique', 'top', 'freq', 'mean', 'std', 'min', '25%', '50%', '75%', 'max'])
#     filename  = DAILY_MALWARE/f'{key} ({malcol.today}).csv'
#     df = pd.read_csv(filename)
#     df['url'] = df['url'].astype(str)
#     head = df.head()
#     for col in df.columns:
#         head[col] = head[col].astype(str)[:20]
        
    
#     df[df['url'].str.len()>10].head().to_csv(f'{key}.csv', index=False)
    
    
    
#     rep["Column Name"] = df.columns 
#     rep['Description'] = list(df.dtypes)
    
    
#     for i, row in rep.iterrows():
#         desc = df[row['Column Name']].describe()
#         rep.at[i, desc.index] = desc
#     rep.rename(columns = {'count':'Non-Null Count', 'unique':'Distinct Count', 'min':'Min.','max':"Max.", 'mean':'Avg.', "std":'Std. Dev.'}, inplace=True)
#     rep = rep[['Column Name','Description', 'Non-Null Count', 'Distinct Count', 'Min.', 'Max.', 'Avg.', 'Std. Dev.']]
    
#     rep.to_csv(f'{key}.csv', index=False)
    
    

    
    
    

    
    
    