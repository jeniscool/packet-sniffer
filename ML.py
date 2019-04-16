import pandas as pd 
import numpy as np
import csv 
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.svm import SVC
from sklearn.svm import LinearSVC
from sklearn import tree
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score


df = pd.read_csv("data/data.csv", header=None)
write_file = 'test.csv'
test_size = .25
# You might not need this next line if you do not care about losing information
# about flow_id etc. All you actually need to
# feed your machine learning model are features and output label.
columns_list = ['flow_id', 'IPsrc', 'IPdst', 'proto', 'time', 'num_packets', 'sport', 'dport', 'avg_packet_size', 'label']
df.columns = columns_list
features = ['proto', 'time', 'num_packets', 'sport', 'dport', 'avg_packet_size']

Features = df[features]
Labels = df['label']

with open(write_file, 'a') as w:
    w.write('Machine Learning Data, , ,Accuracy, Precision, Recall, F1\n')

acc_scores = 0
for i in range(0, 10):
    # Split the data set into training set and testing set

    Features_train, Features_test, Labels_train, Labels_test = train_test_split(Features, Labels, test_size=test_size)

    # Decision Trees
    dt = tree.DecisionTreeClassifier()
    dt.fit(Features_train, Labels_train)
    dt_predict = dt.predict(Features_test)

    dt_result = dt.score(Features_test, Labels_test)  # accuracy score

    dt_precision = precision_score(Labels_test, dt_predict, average='micro')  # precision score
    dt_recall = recall_score(Labels_test, dt_predict, average='micro')  # recall score
    dt_f1 = f1_score(Labels_test, dt_predict, average='micro')  # f1 score

    # Neural network (MultiPerceptron Classifier)
    nn = MLPClassifier()
    nn.fit(Features_train, Labels_train)
    nn_predict = nn.predict(Features_test)

    nn_result = nn.score(Features_test, Labels_test)  # accuracy score
    nn_precision = precision_score(Labels_test, nn_predict, average='micro')  # precision score
    nn_recall = recall_score(Labels_test, nn_predict, average='micro')  # recall score
    nn_f1 = f1_score(Labels_test, nn_predict, average='micro')  # f1 score

    # SVMs
    svm = SVC(gamma='auto')     # SVC USE THIS
    # svm = LinearSVC()  #Linear SVC
    svm.fit(Features_train, Labels_train)
    svm_predict = svm.predict(Features_test)

    svm_result = svm.score(Features_test, Labels_test)  # accuracy score
    svm_precision = precision_score(Labels_test, svm_predict, average='micro')  # precision score
    svm_recall = recall_score(Labels_test, svm_predict, average='micro')  # recall score
    svm_f1 = f1_score(Labels_test, svm_predict, average='micro')  # f1 score

    with open(write_file, 'a') as w:
        w.write(f'Iteration {i}, test_size = {test_size}, ')
        w.write(f',Decision Tree: , {dt_result}, {dt_precision}, {dt_recall}, {dt_f1}, ')
        w.write(f',Neural Network: , {nn_result}, {nn_precision}, {nn_recall}, {nn_f1}, ')
        w.write(f',SVM: , {svm_result}, {svm_precision}, {svm_recall}, {svm_f1}, \n')
