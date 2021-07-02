# Modul:            Praxis-/Bachelorprojekt
# Thema:            Detect Malicious Login Events
# Autorenschaft:    Richard Mey <richard.mey@syss.de>
# Stand:            16.06.2021

# Funktionsdefinition für den knn mit Ausgabepfad+Anzahl an Kernen
def knn_exec(source_path, path, cores, rank, mean_rank, load_model, save_model, model_path, config_data=None):
    # Laden der nötigen Bibliotheken
    import sys
    sys.path.insert(1, source_path + "maliciousevents/lib/python3.8/site-packages/")
    sys.path.insert(1, source_path + "ml/")
    import pandas as pd
    from pyod.models.knn import KNN
    from joblib import dump, load
    # https://stackoverflow.com/questions/4383571/importing-files-from-different-folder
    import Pre_and_post_processing as pp

    # Einlesen der Features
    features = pd.read_csv((path + "Features.csv"), index_col=0)

    columns = features.columns.values.tolist()

    if "hour" in columns:
        hours, features = pp.convert_hours(features)

    if "day" in columns:
        days, features = pp.convert_days(features)

    if not load_model:
        if config_data is not None:
            model = KNN(contamination=config_data['contamination'], n_neighbors=config_data['n_neighbors'],
                        method=config_data['method'], algorithm=config_data['algorithm'], n_jobs=cores,
                        metric=config_data['metric'])
        else:
            # Erstellen des Models IF mit den Hyperparametern
            model = KNN(contamination=0.0001, n_neighbors=20, method="mean", algorithm="ball_tree", n_jobs=cores)

        # Trainieren des kNNs
        model.fit(features)
    else:
        model = load(model_path + 'model.joblib')

        if str(type(model)) != "<class 'pyod.models.knn.KNN'>":
            print("Use the correct model on load with the correct machine learning option.")
            sys.exit(1)

    if save_model:
        dump(model, path + 'model/' + 'model.joblib')

    # Vorhersage/Auslesen des Scores und ob es dadurch einer Anomaly entspricht
    try:
        pred = model.labels_
        scores = model.decision_scores_
    except:
        print("The features of the data should be the same like the model features.")
        sys.exit(1)

    try:
        features['anomaly'] = pred
        features['scores'] = scores
    except ValueError:
        print("kNN ist not able to use two data sets for prediction and training.")
        sys.exit(1)
    # Sortieren nach Score
    features = features.sort_values(by=['scores'], ascending=False)

    if "hour" in columns:
        features['hour'] = hours

    if "day" in columns:
        features['day'] = days

    # Anomalien in die Ausgabe schreiben
    if not rank:
        features.loc[features['anomaly'] == 1].to_csv(path + 'results.csv')
    else:
        if mean_rank:
            res = pp.rank_mean(features)
        else:
            res = pp.rank_first(features)
        res.to_csv(path + 'results.csv')
