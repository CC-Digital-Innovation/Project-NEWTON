import pandas as pd
import json
import pydotplus
from sklearn import tree
from sklearn.tree import DecisionTreeClassifier
import matplotlib.pyplot as plot
import matplotlib.image as img


#Creates a decision tree and trains it using a training set in trainset.json
def train_tree():
    #open and read contents of trainset
    with open("trainset.json", "r") as f:
        train_data_json = f.read()

    #put training set into pandas df
    df = pd.read_json(train_data_json)
    features = ["CVSS3", "CVSS2", "ManRank"]

    #split set into training and target values
    train = df[features]
    target = df["Actionable"]

    #create decision tree and fit with training values
    dectree = DecisionTreeClassifier()
    dectree = dectree.fit(train.values, target)

    return dectree

#Create a png of the decision tree using graphviz
def graph_tree(dectree: DecisionTreeClassifier,features):
    data = tree.export_graphviz(dectree, out_file=None, feature_names=features)
    graph = pydotplus.graph_from_dot_data(data)
    graph.write_png("dectree.png")

    helo = img.imread("dectree.png")
    plt = plot.imshow(helo)
    plot.show()

#Run predictions on incoming values
def predict(dectree: DecisionTreeClassifier, values):
    predict = dectree.predict(values)
    return predict