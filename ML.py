import pandas as pd 
import numpy as np
import csv 
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.svm import SVC
from sklearn.svm import LinearSVC
from sklearn import tree



df = pd.read_csv("data.csv", header=None)
# You might not need this next line if you do not care about losing information about flow_id etc. All you actually need to
# feed your machine learning model are features and output label.
columns_list = ['flow_id', 'IPsrc', 'IPdst', 'proto', 'time', 'num_packets', 'sport', 'dport', 'avg_packet_size', 'label']
df.columns = columns_list
features = ['proto', 'time', 'num_packets', 'sport', 'dport', 'avg_packet_size']

Features = df[features]
Labels = df['label']

acc_scores = 0
for i in range(0, 10):
    # Split the data set into training set and testing set
    Features_train, Features_test, Labels_train, Labels_test = train_test_split(Features, Labels, test_size = 0.25)

    #Decision Trees
    clf = tree.DecisionTreeClassifier()
    clf.fit(Features_train, Labels_train)

    # Neural network (MultiPerceptron Classifier)
    # clf = MLPClassifier()
    # clf.fit(Features_train, Labels_train)

    #SVM's
    # clf = SVC(gamma='auto')     #SVC USE THIS
    # clf = LinearSVC()  #Linear SVC
    # clf.fit(Features_train, Labels_train)


    #here you are supposed to calculate the evaluation measures indicated in the project proposal (accuracy, F-score etc)
    result = clf.score(Features_test, Labels_test)  #accuracy score
    print(result)