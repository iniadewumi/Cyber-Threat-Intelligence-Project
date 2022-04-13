import pandas as pd
import pathlib
import matplotlib.pyplot as plt
from scipy import sparse
from sklearn.preprocessing import LabelBinarizer
from sklearn.multiclass import OneVsRestClassifier
import seaborn as sns

ROOT = pathlib.Path().resolve()
DATA = ROOT / 'Data'
CSV = DATA / 'CSVs'



df = pd.read_csv(CSV/'processed_dataframe.csv')

y_dense = LabelBinarizer().fit_transform(df['type'])
y_sparse = sparse.csr_matrix(y_dense)
df['Cat'] = y_sparse


#TRAIN
X = df.drop(['url','type','Category','domain'],axis=1)#,'type_code'
y = df['Category']

plt.figure(figsize=(12,6))
sns.boxplot(df=df,x='Type',y='URL_LENGTH')
plt.figure(figsize=(12,6))
sns.boxplot(df=df,x='Type',y='NUMBER_SPECIAL_CHARACTERS')
plt.figure(figsize=(15, 15))
sns.heatmap(df.corr(), linewidths=.5)
