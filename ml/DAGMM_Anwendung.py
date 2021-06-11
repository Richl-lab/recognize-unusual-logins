# https://github.com/tnakae/DAGMM/blob/master/Example_DAGMM.ipynb
def dagmm_exec(source_path, path, cores, rank, load_model, save_model, model_path):
    import tensorflow as tf
    import numpy as np
    import pandas as pd
    import joblib

    from dagmm import DAGMM

    # https://stackoverflow.com/questions/4383571/importing-files-from-different-folder
    import sys
    sys.path.insert(1, source_path)
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
    features.set_index(rownames)

    if "Stunde" in columns:
        hours, features = pp.convert_hours(features)

    if "Tag" in columns:
        days, features = pp.convert_days(features)

    model_dagmm = DAGMM(
        comp_hiddens=[23, 16, 8, 4, 2], comp_activation=tf.nn.tanh,
        est_hiddens=[26, 13], est_activation=tf.nn.tanh, est_dropout_ratio=0.25,
        epoch_size=2500, minibatch_size=512, random_seed=123
    )

    model_dagmm.fit(features)

    energy = model_dagmm.predict(features)
    features['scores'] = energy
    features = features.sort_values(by=['scores'], ascending=False)

    if "Stunde" in columns:
        features['Stunde'] = hours

    if "Tag" in columns:
        features['Tag'] = days

    # Anomalien in die Ausgabe schreiben
    if not rank:
        anomaly_threshold = np.percentile(energy, 99.99)
        anomaly = features['scsores'] >= anomaly_threshold
        features[anomaly].to_csv(path + 'Ergebnisse.csv')
    else:
        res = pp.rank(features)
        res.to_csv(path + 'Ergebnisse.csv')

