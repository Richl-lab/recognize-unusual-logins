# Modul:            Praxis-/Bachelorprojekt
# Thema:            Detect Malicious Login Events
# Autorenschaft:    Richard Mey <richard.mey@syss.de>
# Stand:            16.06.2021

# https://github.com/tnakae/DAGMM/blob/master/Example_DAGMM.ipynb
def dagmm_exec(source_path, path, rank, mean_rank, load_model, save_model, model_path, config_data=None):
    import sys
    sys.path.insert(1, source_path + "maliciousevents/lib/python3.8/site-packages/")
    sys.path.insert(1, source_path + "ml/")
    import tensorflow as tf
    import numpy as np
    import pandas as pd
    import joblib

    from dagmm import DAGMM

    # https://stackoverflow.com/questions/4383571/importing-files-from-different-folder
    import Pre_and_post_processing as pp

    # Einlesen der Features
    features = pd.read_csv((path + "Features.csv"), index_col=0)
    rownames = features.index.values
    columns = features.columns.values.tolist()

    # Übersetzen der Identifier Variable in eine kategoriale
    features[['Identifier']] = features[['Identifier']].astype('category')
    groups = pd.get_dummies(features[["Identifier"]])
    features = features.drop(["Identifier"], axis=1)
    features = pd.concat([features.reset_index(drop=True), groups.reset_index(drop=True)], axis=1)
    features = features.set_index(rownames)

    if "hour" in columns:
        hours, features = pp.convert_hours(features)

    if "day" in columns:
        days, features = pp.convert_days(features)

    column_width = len(features.columns)

    if config_data is not None:
        model_dagmm = DAGMM(
            comp_hiddens=config_data['comp_hiddens'],
            comp_activation=config_data['comp_activation'],
            est_hiddens=config_data['est_hiddens'], est_activation=config_data['est_activation'],
            est_dropout_ratio=config_data['est_dropout_ratio'],
            epoch_size=config_data['epoch_size'], minibatch_size=config_data['minibatch_size'],
            random_seed=config_data['random_seed']
        )
    else:
        model_dagmm = DAGMM(
            comp_hiddens=[column_width, int(0.75 * column_width), int(0.5 * column_width), 4, 2],
            comp_activation=tf.nn.tanh,
            est_hiddens=[16, 8, 4], est_activation=tf.nn.tanh, est_dropout_ratio=0.25,
            epoch_size=2500, minibatch_size=512, random_seed=123
        )

    if not load_model:
        model_dagmm.fit(features)
    else:
        try:
            model_dagmm.restore(model_path)
        except OSError:
            print("Use the correct model on load with the correct machine learning option.")
            sys.exit(1)

    if save_model:
        model_dagmm.save(path + 'model/')

    energy = model_dagmm.predict(features)
    features['scores'] = energy
    features = features.sort_values(by=['scores'], ascending=False)

    if "hour" in columns:
        features['hour'] = hours

    if "day" in columns:
        features['day'] = days

    # Anomalien in die Ausgabe schreiben
    if not rank:
        anomaly_threshold = np.percentile(energy, 99.99)
        anomaly = features['scores'] >= anomaly_threshold
        features[anomaly].to_csv(path + 'results.csv')
    else:
        if mean_rank:
            res = pp.rank_mean(features)
        else:
            res = pp.rank_first(features)
        res.to_csv(path + 'results.csv')
