# Funktionsdefinition für den knn mit Ausgabepfad+Anzahl an Kernen
def knn_exec(source_path, path, cores, rank, load_model, save_model, model_path):
    # Laden der nötigen Bibliotheken
    import sys
    sys.path.insert(1, source_path + "maliciousevents/lib/python3.8/site-packages/")
    sys.path.insert(1, source_path+"ml/")
    import pandas as pd
    from pyod.models.knn import KNN
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
        model = KNN(contamination=0.0001, n_neighbors=20, method="mean", algorithm="ball_tree", n_jobs=cores)

        # Trainieren des kNNs
        model.fit(features)
    else:
        model = load(model_path + 'model.joblib')

    if save_model:
        dump(model, path + 'model/' + 'model.joblib')

    # Vorhersage/Auslesen des Scores und ob es dadurch einer Anomaly entspricht
    pred = model.labels_
    scores = model.decision_scores_
    features['anomaly'] = pred
    features['scores'] = scores
    # Sortieren nach Score
    features = features.sort_values(by=['scores'], ascending=False)

    if "Stunde" in columns:
        features['Stunde'] = hours

    if "Tag" in columns:
        features['Tag'] = days

    # Anomalien in die Ausgabe schreiben
    if not rank:
        features.loc[features['anomaly'] == 1].to_csv(path + 'Ergebnisse.csv')
    else:
        res = pp.rank(features)
        res.to_csv(path + 'Ergebnisse.csv')
