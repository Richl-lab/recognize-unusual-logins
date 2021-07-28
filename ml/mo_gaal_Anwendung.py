# Module:            Bachelor thesis
# Theme:             Detect malicious/unusual Login Events
# Author:            Richard Mey <richard.mey@syss.de>
# Status:            28.07.2021

import sys
import re
from pyod.models.mo_gaal import MO_GAAL
from joblib import load

python_script_directory = re.sub("maliciousevents/bin/python", "", sys.argv[0]) + "ml/"
sys.path.insert(1, python_script_directory)
import Pre_and_post_processing as pp


def mo_gaal_exec(path, data_path, cores, rank, rank_method, load_model, save_model, model_path, config_data):
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
        pp.persist_rank_result(rank_method, path, features)


def create_model(config_data, cores):
    model = MO_GAAL(k=10, stop_epochs=20, lr_d=0.01, lr_g=0.0001, decay=1e-06, momentum=0.9, contamination=0.001)
    return model


def validate_loaded_model(model):
    if str(type(model)) != "<class 'pyod.models.mo_gaal.MO_GAAL'>":
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
