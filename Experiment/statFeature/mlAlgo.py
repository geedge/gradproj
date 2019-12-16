from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn import tree
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score,recall_score,precision_score
import random
import matplotlib.pyplot as plt
%matplotlib inline

PREFIX_DIR = "/Users/Leo/Documents/github/GradProj/"


def RF():
    classifer = RandomForestClassifier()
    classifer.fit(x_train, y_train)
    y_pred = classifer.predict(x_test)
    f1_score_list.append(f1_score(y_test, y_pred, average='micro'))
    recall_score_list.append(recall_score(y_test, y_pred, average='micro'))
    precision_score_list.append(precision_score(y_test, y_pred, average='micro'))
    scores = [np.mean(precision_score_list), np.mean(recall_score_list), np.mean(f1_score_list)]
    score_df.loc['RandomForest'] = scores
    score_df.plot.bar()
    print(scores)

def main():
    date = sys.argv[1]
    example_csv_file = PREFIX_DIR + 'Experiment/statFeature/csvFile/' + date + '/examples.csv'
    examples_df = pd.read_csv(example_csv_file)
    class_counts = examples_df['label'].value_counts().plot.bar()
    examples = examples_df.values.copy()
    score_df = pd.DataFrame(np.zeros((5,3)),index = ['LogisticRegression', 'SVM', 'GaussianNB', 'tree', 'RandomForest'], \
                        columns = ['precision', 'recall', 'f1'])
    f1_score_list = list()
    recall_score_list = list()
    precision_score_list = list()
    for i in range(50):
        np.random.shuffle(examples)
        examples_train = examples[:int(len(examples)*0.75)]
        examples_test = examples[int(len(examples)*0.75):]
        x_train = examples_train[:,0:-1]
        y_train = examples_train[:,-1]
        x_test = examples_test[:,0:-1]
        y_test = examples_test[:,-1]
        RF(score_df, f1_score_list, recall_score_list, precision_score_list, \
            x_train, y_train, x_test, y_test)



if __name__ == '__main__':
    main()