# Modul:            Praxis-/Bachelorprojekt
# Thema:            Detect Malicious Login Events
# Autorenschaft:    Richard Mey <richard.mey@syss.de>
# Stand:            16.06.2021

import sys
import re
from pyod.models.knn import KNN
from pyod.models.iforest import IForest
from pyod.models.lscp import LSCP
from joblib import load

python_script_directory = re.sub("maliciousevents/bin/python", "", sys.argv[0]) + "ml/"
sys.path.insert(1, python_script_directory)
import Pre_and_post_processing as pp


def lscp_exec(path, data_path, cores, rank, mean_rank, load_model, save_model, model_path, config_data):
    features = pp.read_features(data_path)

    columns = pp.get_column_names(features)

    hours, days, features = pp.convert_time_features(features, columns)

    if not load_model:
        model = create_model(config_data, cores)
        model.fit(features)
    else:
        model = load(model_path + 'model.joblib')
        validate_loaded_model(model)

    pp.save_model_to_path(model, path, save_model)

    pred, scores = predict(model, features)

    features = insert_prediction_to_features(pred, scores, features)

    features = pp.sort_features(features, ascending=False)

    features = pp.convert_time_features_back(features, columns, hours, days)

    if not rank:
        pp.persist_result(features, path, anomaly_id=1)
    else:
        pp.persist_rank_result(mean_rank, path, features)


def create_model(config_data, cores):
    model_knn = KNN(contamination=config_data['contamination'], n_neighbors=config_data['n_neighbors'],
                    method=config_data['method'], algorithm=config_data['algorithm'], n_jobs=cores,
                    metric=config_data['metric'])
    model_if = IForest(n_estimators=50, max_samples='auto', contamination=0.001, max_features=1.0,
                       n_jobs=cores, behaviour='old', random_state=123)
    model = LSCP(detector_list=[model_knn, model_if], random_state=123, contamination=0.001)
    return model


def validate_loaded_model(model):
    if str(type(model)) != "<class 'pyod.models.lscp.LSCP'>":
        print("Use the correct model on load with the correct machine learning option.")
        sys.exit(1)


def predict(model, features):
    try:
        pred = model.predict(features)
        scores = model.decision_function(features)
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
