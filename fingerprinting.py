import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold

from scapy.all import *

def classify(train_features, train_labels, test_features, test_labels):

    """Function to perform classification, using a 
    Random Forest. 

    Reference: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html
    
    Args:
        train_features (numpy array): list of features used to train the classifier
        train_labels (numpy array): list of labels used to train the classifier
        test_features (numpy array): list of features used to test the classifier
        test_labels (numpy array): list of labels (ground truth) of the test dataset

    Returns:
        predictions: list of labels predicted by the classifier for test_features

    Note: You are free to make changes the parameters of the RandomForestClassifier().
    """

    # Initialize a random forest classifier. Change parameters if desired.
    clf = RandomForestClassifier()
    # Train the classifier using the training features and labels.
    clf.fit(train_features, train_labels)
    # Use the classifier to make predictions on the test features.
    predictions = clf.predict(test_features)
    
    return predictions

def perform_crossval(features, labels, folds=10):

    """Function to perform cross-validation.
    Args:
        features (list): list of features
        labels (list): list of labels
        folds (int): number of fold for cross-validation (default=10)
    Returns:
        You can modify this as you like.
    
    This function splits the data into training and test sets. It feeds
    the sets into the classify() function for each fold. 

    You need to use the data returned by classify() over all folds 
    to evaluate the performance.         
    """

    kf = StratifiedKFold(n_splits=folds)
    labels = np.array(labels)
    features = np.array(features)

    testing_set = []

    avg = []
    accuracy_per_point = [0] * 100
    count_per_point = [0] * 100
    for train_index, test_index in kf.split(features, labels):
        X_train, X_test = features[train_index], features[test_index]
        y_train, y_test = labels[train_index], labels[test_index]
        predictions = classify(X_train, y_train, X_test, y_test)


        ###############################################
        # TODO: Write code to evaluate the performance of your classifier
        ###############################################
        result = []
        for i in range(len(y_test)):
            if y_test[i]== predictions[i]:
                accuracy_per_point[y_test[i] - 1] += 1
            count_per_point[y_test[i] - 1] += 1

            result.append(y_test[i] == predictions[i])

        ## Compute total accuracy
        total_accuracy = 0
        for idx, r in enumerate(result):
            if r:
                total_accuracy += 1

        ## Compute accuracy per grid point
        

        print("Pourcentage: ", total_accuracy / len(result) * 100)
        avg.append(total_accuracy / len(result) * 100)


    print("Final result: ", sum(avg) / len(avg))
    # accuracy_per_point = list(map(accuracy_per_point(lambda x: x / 10 * 100)))

    for i in range(len(accuracy_per_point)):
            accuracy_per_point[i] = accuracy_per_point[i] / count_per_point[i] * 100
    print("Per point: ", accuracy_per_point)


def load_data():

    """Function to load data that will be used for classification.

    Args:
        You can provide the args you want.
    Returns:
        features (list): the list of features you extract from every trace
        labels (list): the list of identifiers for each trace
    
    An example: Assume you have traces (trace1...traceN) for cells with IDs in the
    range 1-N.  
    
    You extract a list of features from each trace:
    features_trace1 = [f11, f12, ...]
    .
    .
    features_traceN = [fN1, fN2, ...]

    Your inputs to the classifier will be:

    features = [features_trace1, ..., features_traceN]
    labels = [1, ..., N]

    Note: You will have to decide what features/labels you want to use and implement 
    feature extraction on your own.
    """

    ###############################################
    # TODO: Complete this function. 
    ###############################################

    features = []
    labels = []

    max_len = 0
    for i in range(1, 11):
        for j in range(1, 101):
            print(f"Loading ./traces/{i}/grid{j}_trace{i}.pcap")
            p = rdpcap(f'./traces/{i}/grid{j}_trace{i}.pcap')

            # Feature 1: number of packets 
            np = len(p)

            # Feature 2: time the request took
            t = p[np - 1]['IP']['TCP'].options[2][1][0] - p[0]['IP']['TCP'].options[2][1][0]

            # Feature 3: HTTP packets metadata
            nb = 0
            http_lens = []
            for packet in p:
                if packet['TCP'].payload:
                    # Feature 3.1: Number of HTTP OKs
                    if "HTTP/1.0 200 OK" in packet['TCP'].load.decode('utf-8'):
                        nb += 1

                    # Feature 3.2: Length of each HTTP payload
                    http_lens.append(len(packet['TCP']))


            features.append([np, t, nb] + http_lens)

            # Store the max http packets length to pad the rest of the data 
            # data we use to fit has to be of the same length
            if len(features[len(features) - 1]) > max_len:
                max_len = len(features[len(features) - 1])

            labels.append(j)

    # Pad data with 0s to have arrays of the same length
    for feature in features:
        for i in range(max_len - len(feature)):
            feature.append(0)


    return features, labels
        
def main():

    """Please complete this skeleton to implement cell fingerprinting.
    This skeleton provides the code to perform classification 
    using a Random Forest classifier. You are free to modify the 
    provided functions as you wish.

    Read about random forests: https://towardsdatascience.com/understanding-random-forest-58381e0602d2
    """

    features, labels = load_data()
    # print(features, labels)
    perform_crossval(features, labels, folds=10)
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)