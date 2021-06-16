
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

