# Modul:            Praxis-/Bachelorprojekt
# Thema:            Detect Malicious Login Events
# Autorenschaft:    Richard Mey <richard.mey@syss.de>
# Stand:            16.06.2021

import sys
import re
import pandas as pd
from pyod.models.knn import KNN
from joblib import dump, load

python_script_directory = re.sub("maliciousevents/bin/python", "", sys.argv[0]) + "ml/"
sys.path.insert(1, python_script_directory)
import Pre_and_post_processing as pp


def knn_exec(source_path, path, cores, rank, mean_rank, load_model, save_model, model_path, config_data):
    features = pp.read_features(path)

    columns = pp.get_column_names(features)

    hours, days, features = pp.convert_time_features(features, columns)

    if not load_model:
        model = KNN(contamination=config_data['contamination'], n_neighbors=config_data['n_neighbors'],
                    method=config_data['method'], algorithm=config_data['algorithm'], n_jobs=cores,
                    metric=config_data['metric'])
        # Trainieren des kNNs
        model.fit(features)
    else:
        model = load(model_path + 'model.joblib')

        if str(type(model)) != "<class 'pyod.models.knn.KNN'>":
            print("Use the correct model on load with the correct machine learning option.")
            sys.exit(1)

    pp.save_model_to_path(model, path, save_model)

    pred, scores = predict(model)

    features = insert_prediction_to_features(pred, scores, features)

    features = pp.sort_features(features, ascending=False)

    features = pp.convert_time_features_back(features, columns, hours, days)

    if not rank:
        pp.persist_result(features, path, anomaly_id=1)
    else:
        pp.persist_rank_result(mean_rank, path, features)


def predict(model):
    try:
        pred = model.labels_
        scores = model.decision_scores_
    except:
        print("The features of the data should be the same like the model features.")
        sys.exit(1)

    return pred, scores


def insert_prediction_to_features(pred, scores, features):
    try:
        features['anomaly'] = pred
        features['scores'] = scores
    except ValueError:
        print("kNN ist not able to use two data sets for prediction and training.")
        sys.exit(1)

    return features
