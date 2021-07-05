# Modul:            Praxis-/Bachelorprojekt
# Thema:            Detect Malicious Login Events
# Autorenschaft:    Richard Mey <richard.mey@syss.de>
# Stand:            16.06.2021

import sys
import re
import tensorflow as tf
import numpy as np
import pandas as pd
import joblib
from dagmm import DAGMM

python_script_directory = re.sub("maliciousevents/bin/python", "", sys.argv[0]) + "ml/"
sys.path.insert(1, python_script_directory)
import Pre_and_post_processing as pp


# https://github.com/tnakae/DAGMM/blob/master/Example_DAGMM.ipynb
def dagmm_exec(source_path, path, rank, mean_rank, load_model, save_model, model_path, config_data):
    features = pp.read_features(path)

    rownames = get_rownames(features)
    columns = pp.get_column_names(features)

    features = transform_categorial_variable(features, rownames)

    hours, days, features = pp.convert_time_features(features, columns)

    if config_data['dynamic'] is True:
        column_width = len(features.columns)
        model_dagmm = create_model([column_width, int(0.75 * column_width), int(0.5 * column_width), 4, 2])
    else:
        model_dagmm = create_model(
            comp_hiddens=config_data['comp_hiddens'],
            comp_activation=config_data['comp_activation'],
            est_hiddens=config_data['est_hiddens'], est_activation=config_data['est_activation'],
            est_dropout_ratio=config_data['est_dropout_ratio'],
            epoch_size=config_data['epoch_size'], minibatch_size=config_data['minibatch_size'],
            random_seed=config_data['random_seed']
        )

    if not load_model:
        model_dagmm.fit(features)
    else:
        load_model_dagmm(model_dagmm, model_path)

    if save_model:
        model_dagmm.save(path + 'model/')

    score = predict(features, model_dagmm)
    features['scores'] = score
    features = pp.sort_features(features, ascending=False)

    features = pp.convert_time_features_back(features, columns, hours, days)

    if not rank:
        persist_result(features, score, path)
    else:
        pp.persist_rank_result(mean_rank, path, features)


def get_rownames(features):
    return features.index.values


def transform_categorial_variable(features, rownames):
    features[['Identifier']] = features[['Identifier']].astype('category')
    groups = pd.get_dummies(features[["Identifier"]])
    features = features.drop(["Identifier"], axis=1)
    features = pd.concat([features.reset_index(drop=True), groups.reset_index(drop=True)], axis=1)
    features = features.set_index(rownames)
    return (features)


def create_model(comp_hiddens=None, comp_activation="tanh", est_hiddens=[16, 8, 4], est_activation="tanh", est_dropout_ratio=0.25, epoch_size=2500,
                 minibatch_size=512, random_seed=123):
    model_dagmm = DAGMM(
        comp_hiddens=comp_hiddens,
        comp_activation=comp_activation,
        est_hiddens=est_hiddens, est_activation=est_activation, est_dropout_ratio=est_dropout_ratio,
        epoch_size=epoch_size, minibatch_size=minibatch_size, random_seed=random_seed
    )
    return model_dagmm


def load_model_dagmm(model_dagmm, model_path):
    try:
        model_dagmm.restore(model_path)
    except OSError:
        print("Use the correct model on load with the correct machine learning option.")
        sys.exit(1)

    return model_dagmm


def predict(features, model_dagmm):
    score = model_dagmm.predict(features)
    return score


def persist_result(features, score, path):
    anomaly_threshold = np.percentile(score, 99.99)
    anomaly = features['scores'] >= anomaly_threshold
    features[anomaly].to_csv(path + 'results.csv')
