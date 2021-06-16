
# Add new python machine learning method

## First step

Add an optional console argument:
   ```sh
   if(length(grep("-m",as.character(args)))!=0){
   	if(as.character(args[grep("-m",as.character(args))+1])=="IF" ||as.character(args[grep("-m",as.character(args))+1])=="kNN" || as.character(args[grep("-m",as.character(args))+1])=="DAGMM" || as.character(args[grep("-m",as.character(args))+1])=="RF" || as.character(args[grep("-m",as.character(args))+1])=="YOUR NEW METHOD"){
   		...
   	  	else if(as.character(args[grep("-m",as.character(args))+1])=="YOUR NEW METHOD"){
          			ml<-"YOUR NEW METHOD"
          		}
        		...
   	}
   }
   ```
   
## Second step

Add the execution function:
   ```sh
   if(ml=="IF" || ml=="kNN" || ml=="DAGMM" || ml=="YOUR NEW METHOD"){
   	else if(ml=="YOUR NEW METHOD"){
   		YOUR_NEW_METHOD(absoluter_path,path,cores,rank,load_model,save_model,model_path)
   	}
   }
   ```
   
## Third step   

Add the function that executes the python program:
   ```sh
   YOUR_NEW_METHOD<-function(Input_path,Output_path,cores,rank,load_model,save_model,model_path){
  		source_python(paste(Input_path,"ml/YOUR_NEW_METHOD_Anwendung.py",sep=""))
   	YOUR_NEW_METHOD_exec(Input_path,Output_path,as.integer(cores),rank,load_model,save_model,model_path)
   }
   ```

## Fourth step

Add the python program to the ml directory with the following structure:
   ```sh
   def YOUR_NEW_METHOD_exec(source_path, path, cores, rank, load_model, save_model, model_path):
   import sys
	    sys.path.insert(1, source_path + "maliciousevents/lib/python3.8/site-packages/")
	    sys.path.insert(1, source_path+"ml/")

	    import pandas as pd
	    import Pre_and_post_processing as pp
	    import ML_METHOD
	    # Import the library if needed to save and load the model
	    from joblib import dump, load
	    
	    features = pd.read_csv((path + "Features.csv"), index_col=0)

	    columns = features.columns.values.tolist()

	    if "Stunde" in columns:
		hours, features = pp.convert_hours(features)

	    if "Tag" in columns:
		days, features = pp.convert_days(features)

	    if not load_model:
		# Create the model YOUR_NEW_METHOD with the hyperparameters
		model = YOUR_NEW_METHOD()

		# train the YOUR_NEW_METHOD
		model.fit(features)
	    else:
		model = load(model_path + 'model.joblib')

		if str(type(model)) != "<class 'YOUR_NEW_METHOD'>":
		    print("Use the correct model on load with the correct machine learning option.")
		    sys.exit(1)

	    if save_model:
		dump(model, path + 'model/' + 'model.joblib')

	    # Predict the scores and optional mark it as anomaly
	    try:
		features['scores'] = model.decision_function(features[columns])
		features['anomaly'] = model.predict(features[columns])
	    except:
		print("The features of the data should be the same like the model features.")
		sys.exit(1)

	    # Sort the scores in the correct order
	    features = features.sort_values(by=['scores'], ascending=False)

	    if "Stunde" in columns:
		features['Stunde'] = hours

	    if "Tag" in columns:
		features['Tag'] = days

	    # Write anomalies or ranks in a file
	    if not rank:
		features.loc[features['anomaly'] == 1].to_csv(path + 'Ergebnisse.csv')
	    else:
		res = pp.rank(features)
		res.to_csv(path + 'Ergebnisse.csv')

   ```
  
