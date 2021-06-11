import datetime
import pandas as pd
import re


def convert_hours(features: pd.DataFrame):
    hours = features['Stunde']

    def convert_hour(hour):
        # https://www.kite.com/python/answers/how-to-convert-a-time-string-to-seconds-in-python
        date_time = datetime.datetime.strptime(hour, "%H:%M:%S")
        a_timedelta = date_time - datetime.datetime(1900, 1, 1)
        seconds = a_timedelta.total_seconds()
        return seconds

    secs = map(convert_hour, features['Stunde'].tolist())
    secs = list(secs)
    features['Stunde'] = secs
    return hours, features


def convert_days(features: pd.DataFrame):
    days = features['Tag']

    def convert_day(day):
        date = datetime.datetime.strptime(day, "%Y-%m-%d")
        date_delta = date - datetime.datetime(1900, 1, 1)
        days_delta = date_delta.days
        return days_delta

    days_dif = map(convert_day, features['Tag'].tolist())
    days_dif = list(days_dif)
    features['Tag'] = days_dif
    return days, features


def rank(features: pd.DataFrame):
    rownames = features.index.values.tolist()
    new_names = []
    for names in rownames:
        new_names.append(re.sub('^X', "", re.sub('\\..*$', "", names)))

    res = pd.DataFrame()
    in_res = []
    for i in range(len(new_names)):
        if new_names[i] not in in_res:
            res = res.append(features.iloc[i])
            in_res.append(new_names[i])

    return res
