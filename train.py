import pandas as pd
import pathlib
import matplotlib.pyplot as plt
from scipy import sparse

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelBinarizer, OneHotEncoder
from sklearn.multiclass import OneVsRestClassifier
from sklearn.model_selection import cross_validate
import seaborn as sns

from tld import get_tld, is_tld
pd.options.display.max_columns = 100

from sklearn.model_selection import KFold
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import accuracy_score
import pickle
# manual nested cross-validation for random forest on a classification dataset
from numpy import mean, std


ROOT = pathlib.Path().resolve()
DATA = ROOT / 'Data'
CSV = DATA / 'CSVs'
MALIC = CSV / 'Malicious Datasets'
MODELS = DATA / "Models"

try:
    df = pd.read_csv(MALIC/'processed_dataframe.csv')
except:
    df = pd.read_csv(MALIC/'processed_dataframe.csv.zip')
    






class Training:
    def __init__(self):
        self.df = pd.read_csv(MALIC/'processed_dataframe.csv')
    
# train = Training()


X = df.drop(['url', 'type',  'domain'], axis=1)
y = df['type']

types = y
# plt.bar(types.index, height=types, color=['navy',  'blue', 'purple', 'red'])


kf = KFold(n_splits=3)

outer_results = []
best_list = []

for train_index, test_index in kf.split(X):
    # print("TRAIN:", train_index, "TEST:", test_index)
    X_train, X_test = X.loc[train_index], X.loc[test_index]
    y_train, y_test = y.loc[train_index], y.loc[test_index]


    cv_inner = KFold(n_splits=3, shuffle=True, random_state=1)
    # define the model
    model = RandomForestClassifier(random_state=1)

    # define search space
    space = {'n_estimators': [10, 50, 200], 'max_features': [2, 4, 6]}
    # define search
    search = GridSearchCV(model, space, scoring='accuracy', cv=cv_inner, refit=True, verbose=True)
    result = search.fit(X_train, y_train)

    # get the best performing model fit on the whole training set
    best_model = result.best_estimator_
    yhat = best_model.predict(X_test)
    # evaluate the model
    acc = accuracy_score(y_test, yhat)
    # store the result
    outer_results.append(acc)
    best_list.append(best_model)
    # report progress
    print('\n\n\nacc=%.3f, est=%.3f, cfg=%s' % (acc, result.best_score_, result.best_params_))
# summarize the estimated performance of the model
print('Accuracy: %.3f (%.3f)' % (mean(outer_results), std(outer_results)))

b_model = best_list[outer_results.index(max(outer_results))]

print(b_model)

with open(MODELS/"random_forest.pickle", "wb") as f:
    pickle.dump(b_model, f)


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
