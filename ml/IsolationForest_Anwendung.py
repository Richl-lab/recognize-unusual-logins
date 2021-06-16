# Modul:            Praxis-/Bachelorprojekt
# Thema:            Detect Malicious Login Events
# Autorenschaft:    Richard Mey <richard.mey@syss.de>
# Stand:            16.06.2021

# https://blog.paperspace.com/anomaly-detection-isolation-forest/
# Funktionsdefinition für den Isolationforest mit Ausgabepfad+Anzahl an Kernen
def isolationforest_exec(source_path, path, cores, rank, load_model, save_model, model_path):
    # Laden der nötigen Bibliotheken
    import sys
    sys.path.insert(1, source_path + "maliciousevents/lib/python3.8/site-packages/")
    sys.path.insert(1, source_path+"ml/")

    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from joblib import dump, load
    # https://stackoverflow.com/questions/4383571/importing-files-from-different-folder
    import Pre_and_post_processing as pp

    # Einlesen der Features
    features = pd.read_csv((path + "Features.csv"), index_col=0)

    columns = features.columns.values.tolist()

    if "Stunde" in columns:
        hours, features = pp.convert_hours(features)

    if "Tag" in columns:
        days, features = pp.convert_days(features)

    if not load_model:
        # Erstellen des Models IF mit den Hyperparametern
        model = IsolationForest(n_estimators=50, max_samples='auto', contamination=float(0.0001), max_features=1.0,
                                n_jobs=cores, random_state=123)

        # Trainieren der Bäume
        model.fit(features)
    else:
        model = load(model_path+'model.joblib')

        if str(type(model)) != "<class 'sklearn.ensemble._iforest.IsolationForest'>":
            print("Use the correct model on load with the correct machine learning option.")
            sys.exit(1)

    if save_model:
        dump(model, path + 'model/' + 'model.joblib')

    # Vorhersage/Auslesen des Scores und ob es dadurch einer Anomaly entspricht
    try:
        features['scores'] = model.decision_function(features[columns])
        features['anomaly'] = model.predict(features[columns])
    except:
        print("The features of the data should be the same like the model features.")
        sys.exit(1)
    # Sortieren nach Score
    features = features.sort_values(by=['scores'], ascending=True)

    if "Stunde" in columns:
        features['Stunde'] = hours

    if "Tag" in columns:
        features['Tag'] = days

    # Anomalien in die Ausgabe schreiben
    if not rank:
        features.loc[features['anomaly'] == -1].to_csv(path + 'Ergebnisse.csv')
    else:
        res = pp.rank(features)
        res.to_csv(path + 'Ergebnisse.csv')
