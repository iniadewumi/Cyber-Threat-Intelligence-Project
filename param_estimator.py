

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