import requests, json
import pathlib


ROOT = pathlib.Path().resolve()
DATA = ROOT / 'Data'
CSV = DATA / 'CSVs'
MALIC = CSV / 'Malicious Datasets'

# ip = "129.118.6.3"
# url = f'https://geolocation-db.com/jsonp/{ip}'




# resp = requests.get(url)
# text = resp.text.replace("callback(", "").replace(")", "")
# json.loads(text)
 
import ipinfo

token = '07231281158dd1'
handler = ipinfo.getHandler(token)
details = handler.getDetails(ip)
details.all
