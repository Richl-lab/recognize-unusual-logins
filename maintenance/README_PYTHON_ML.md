
# Add new python machine learning methode

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
