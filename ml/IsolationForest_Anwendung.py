# https://blog.paperspace.com/anomaly-detection-isolation-forest/
# Funktionsdefinition für den Isolationforest mit Ausgabepfad+Anzahl an Kernen
def isolationforest_exec(path, cores, rank, load_model, save_model, model_path):
    # Laden der nötigen Bibliotheken
    import datetime
    import pandas as pd
    import re
    from sklearn.ensemble import IsolationForest
    from joblib import dump, load

    # Einlesen der Features
    features = pd.read_csv((path + "Features.csv"), index_col=0)

    columns = features.columns.values.tolist()

    if "Stunde" in columns:
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

    if not load_model:
        # Erstellen des Models IF mit den Hyperparametern
        model = IsolationForest(n_estimators=50, max_samples='auto', contamination=float(0.0001), max_features=1.0,
                                n_jobs=cores, random_state=123)

        # Trainieren der Bäume
        model.fit(features)
    else:
        model = load(model_path+'model.joblib')

    if save_model:
        dump(model, path +'model/'+'model.joblib')

    # Vorhersage/Auslesen des Scores und ob es dadurch einer Anomaly entspricht
    features['scores'] = model.decision_function(features[columns])
    features['anomaly'] = model.predict(features[columns])
    # Sortieren nach Score
    features = features.sort_values(by=['scores'], ascending=True)

    if "Stunde" in columns:
        features['Stunde'] = hours

    # Anomalien in die Ausgabe schreiben
    if not rank:
        features.loc[features['anomaly'] == -1].to_csv(path + 'Ergebnisse.csv')
    else:
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

        res.to_csv(path + 'Ergebnisse.csv')
