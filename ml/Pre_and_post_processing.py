# Modul:            Praxis-/Bachelorprojekt
# Thema:            Detect Malicious Login Events
# Autorenschaft:    Richard Mey <richard.mey@syss.de>
# Stand:            16.06.2021

import datetime
import pandas as pd
import re
import numpy as np


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


def extract_index(features: pd.DataFrame):
    rownames = features.index.values.tolist()
    new_names = []
    for names in rownames:
        new_names.append(re.sub('^X', "", re.sub('\\..*$', "", names)))
    return new_names


def rank_first(features: pd.DataFrame):
    new_names = extract_index(features)
    res = pd.DataFrame()
    in_res = []
    for i in range(len(new_names)):
        if new_names[i] not in in_res:
            res = res.append(features.iloc[i])
            in_res.append(new_names[i])

    return res


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
