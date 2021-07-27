# Modul:            Praxis-/Bachelorprojekt
# Thema:            Detect Malicious Login Events
# Autorenschaft:    Richard Mey <richard.mey@syss.de>
# Stand:            16.06.2021

import sys
import re
from sklearn.ensemble import IsolationForest
from joblib import load

python_script_directory = re.sub("maliciousevents/bin/python", "", sys.argv[0]) + "ml/"
sys.path.insert(1, python_script_directory)
import Pre_and_post_processing as pp


# https://blog.paperspace.com/anomaly-detection-isolation-forest/
def isolationforest_exec(path, data_path, cores, rank, rank_method, load_model, save_model, model_path,
                         config_data):
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

    features = predict(features, model, columns)

    features = pp.sort_features(features, ascending=True)

    features = pp.convert_time_features_back(features, columns, hours, days)

    if not rank:
        pp.persist_result(features, path, anomaly_id=-1)
    else:
        pp.persist_rank_result(rank_method, path, features)


def create_model(config_data, cores):
    model = IsolationForest(n_estimators=config_data['n_estimators'], max_samples=config_data['max_samples'],
                            contamination=float(config_data['contamination']),
                            max_features=config_data['max_features'],
                            n_jobs=cores, random_state=config_data['random_state'])
    return model


def validate_loaded_model(model):
    if str(type(model)) != "<class 'sklearn.ensemble._iforest.IsolationForest'>":
        print("Use the correct model on load with the correct machine learning option.")
        sys.exit(1)


def predict(features, model, columns):
    try:
        features['scores'] = model.decision_function(features[columns])
        features['anomaly'] = model.predict(features[columns])
    except:
        print("The features of the data should be the same like the model features.")
        sys.exit(1)

    return features
