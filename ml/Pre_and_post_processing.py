# Module:            Bachelor thesis
# Theme:             Detect malicious/unusual Login Events
# Author:            Richard Mey <richard.mey@syss.de>
# Status:            28.07.2021

import datetime
import pandas as pd
import re
import numpy as np
from joblib import dump


def read_features(data_path):
    features = pd.read_csv(data_path, index_col=0)
    return features


def get_column_names(features):
    columns = features.columns.values.tolist()
    return columns


def convert_time_features(features, columns):
    if "hour" in columns:
        hours, features = convert_hours(features)
    else:
        hours = None
    if "day" in columns:
        days, features = convert_days(features)
    else:
        days = None

    return hours, days, features


def convert_hours(features: pd.DataFrame):
    hours = features['hour']

    def convert_hour(hour):
        # https://www.kite.com/python/answers/how-to-convert-a-time-string-to-seconds-in-python
        date_time = datetime.datetime.strptime(hour, "%H:%M:%S")
        a_timedelta = date_time - datetime.datetime(1900, 1, 1)
        seconds = a_timedelta.total_seconds()
        return seconds

    secs = map(convert_hour, features['hour'].tolist())
    secs = list(secs)
    features['hour'] = secs
    return hours, features


def convert_days(features: pd.DataFrame):
    days = features['day']

    def convert_day(day):
        date = datetime.datetime.strptime(day, "%Y-%m-%d")
        date_delta = date - datetime.datetime(1900, 1, 1)
        days_delta = date_delta.days
        return days_delta

    days_dif = map(convert_day, features['day'].tolist())
    days_dif = list(days_dif)
    features['day'] = days_dif
    return days, features


def save_model_to_path(model, path, save_model):
    if save_model:
        dump(model, path + 'model/' + 'model.joblib')


def sort_features(features, ascending):
    sorted_features = features.sort_values(by=['scores'], ascending=ascending)
    return sorted_features


def convert_time_features_back(features, columns, hours, days):
    if "hour" in columns:
        features['hour'] = hours

    if "day" in columns:
        features['day'] = days

    return features


def persist_result(features, path, anomaly_id):
    features.loc[features['anomaly'] == anomaly_id].to_csv(path + 'results.csv')


def persist_rank_result(rank_method, path, features):
    if rank_method == "m":
        res = rank_mean(features)
    elif rank_method == "v":
        res = rank_with_var(features)
    else:
        res = rank_first(features)
    res.to_csv(path + 'results.csv')


def rank_first(features: pd.DataFrame):
    new_names = extract_index(features)
    res = pd.DataFrame()
    in_res = []
    for i in range(len(new_names)):
        if new_names[i] not in in_res:
            res = res.append(features.iloc[i])
            in_res.append(new_names[i])

    return res


def extract_index(features: pd.DataFrame):
    rownames = features.index.values.tolist()
    new_names = []
    for names in rownames:
        new_names.append(re.sub('^X', "", re.sub('\\..*$', "", names)))
    return new_names


def rank_mean(features: pd.DataFrame):
    new_names = extract_index(features)
    rownames = list(set(new_names))
    new_names = np.array(new_names)

    means = []
    for names in rownames:
        row_numbers = list(np.where(new_names == names)[0])
        means.append(features["scores"].iloc[row_numbers].mean())

    res = pd.DataFrame({"mean_score": means}, index=rownames)
    return res


def rank_with_var(features: pd.DataFrame):
    pd.options.mode.chained_assignment = None
    new_names = extract_index(features)
    rownames = list(set(new_names))
    features['scores'] = (features['scores'] - features['scores'].min()) / (
            features['scores'].max() - features['scores'].min())
    features_without_scores = features.drop(['scores', 'anomaly', 'Identifier'], axis=1, errors='ignore')
    users_with_vars = pd.DataFrame(columns=features_without_scores.columns)

    features_manipulated_score = calc_var_and_new_score_per_user(new_names, rownames,
                                                                 features_without_scores, users_with_vars, features)

    sorted_features = features_manipulated_score.sort_values(by=['scores'], ascending=False)
    first_ranked_features = rank_first(sorted_features)
    return first_ranked_features


def calc_var_and_new_score_per_user(new_names, rownames, features_without_scores, users_with_vars, features):
    for i in range(len(rownames)):
        rows = np.where(np.array(new_names) == rownames[i])
        features_per_view = features_without_scores.iloc[rows]
        var_per_view = features_per_view.var()
        users_with_vars.loc[rownames[i]] = var_per_view
        features['scores'].iloc[rows] = features['scores'].iloc[rows] * users_with_vars['Hosts_per_User'].loc[
            rownames[i]]

    return features
