import pandas as pd
import pathlib
import matplotlib.pyplot as plt
from scipy import sparse

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
# from sklearn.preprocessing import LabelBinarizer, OneHotEncoder
# from sklearn.multiclass import OneVsRestClassifier
# from sklearn.model_selection import cross_validate
# import seaborn as sns

from tld import get_tld, is_tld
pd.options.display.max_columns = 100

from sklearn.model_selection import KFold
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import accuracy_score
import pickle
# manual nested cross-validation for random forest on a classification dataset
from numpy import mean, std
import pickle

ROOT = pathlib.Path().resolve()
DATA = ROOT / 'Data'
CSV = DATA / 'CSVs'
MALIC = CSV / 'Malicious Datasets'
MODELS = DATA / "Models"

# try:
#     df = pd.read_csv(MALIC/'processed_dataframe.csv')
# except:
#     df = pd.read_csv(MALIC/'processed_dataframe.csv.zip')
    
    
    
import re
from urllib.parse import urlparse 
from tld import get_tld, is_tld
from ip_re import ip_re, short_re
import string

from sklearn.linear_model import LinearRegressio

class Training:
    def __init__(self):
        try:
            self.df = pd.read_csv(MALIC/'processed_dataframe.csv')
        except:
            self.df = pd.read_csv(MALIC/'processed_dataframe.csv.zip')
            
        self.X = self.df.drop(['url', 'type',  'domain'], axis=1)
        self.y = self.df['type']
        self.X_train, self.X_test, self.y_train, self.y_test =  train_test_split(self.X, self.y, test_size=0.25, random_state =1)

        self.model = RandomForestClassifier(max_features=6, n_estimators=200, random_state=1,n_jobs=-1, verbose=True)
        self.kf = KFold(n_splits=3)
        self.results = []
        
    def var_imp(self):
        model = LinearRegression()
        # fit the model
        model.fit(X, y)
        # get importance
        importance = model.coef_
        # summarize feature importance
        for i,v in enumerate(importance):
        	print('Feature: %0d, Score: %.5f' % (i,v))
        # plot feature importance
        pyplot.bar([x for x in range(len(importance))], importance)
        pyplot.show()
    
    def train(self):
        # c = 0 
        # for train_index, test_index in self.kf.split(self.X):
            # c+=1

        # X_train, X_test = self.X.loc[train_index], self.X.loc[test_index]
        # y_train, y_test = self.y.loc[train_index], self.y.loc[test_index]
            
        space = {'n_estimators': [10, 50, 200], 'max_features': [2, 4, 6]}
        # define search
        search = GridSearchCV(self.model, space, scoring='accuracy', refit=True, verbose=True)
        result = search.fit(self.X_train, self.y_train)
    
        # get the best performing model fit on the whole training set
        best_model = result.best_estimator_
        yhat = best_model.predict(self.X_test)
        # self.model.fit(self.X_train, self.y_train)
        
        yhat = self.model.predict(self.X_test)
        acc = accuracy_score(self.y_test, yhat)
        print(f"Accuracy at fit: {acc}")
        self.results.append(acc)
        self.save_model()
        
        
    def save_model(self):
        n = sum(1 for x in MODELS.iterdir())
        with open(MODELS/f"random_forest {n}.pickle", "wb") as f:
            pickle.dump(self.model, f)
            
train = Training()
train.train()





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
        
        # train = Training()

# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=111)

# estimator = RandomForestClassifier(n_estimators=200)
# estimator.fit(X,y)
# cross_validate(estimator, X, y)
# cross_validate(estimator, X_test, y_test)



    

# y_dense = LabelBinarizer().fit_transform(df['type'])
# # y_sparse = sparse.csr_matrix(y_dense)
# # df['Cat'] = y_sparse


# #TRAIN
# X = df.drop(['url','type','Category','domain'],axis=1)
# y = df['Category']

# plt.figure(figsize=(12,6))
# sns.boxplot(df=df,x='Type',y='URL_LENGTH')
# plt.figure(figsize=(12,6))
# sns.boxplot(df=df,x='Type',y='NUMBER_SPECIAL_CHARACTERS')
# plt.figure(figsize=(15, 15))
# sns.heatmap(df.corr(), linewidths=.5)
