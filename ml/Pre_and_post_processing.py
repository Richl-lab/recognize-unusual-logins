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
