
# Add a new feature for extraction

## First step

Insert the new function:
   ```sh
   feature_extraction<-function(...){
     ...
     NEW_FUNCTION<-function(ARGUMENTS_NEED,...){
       return(FUNCTION)
     }
     ...
}
   ```
## Second step

Add the function to the list it iterates over in the feature extract function. If it depends from the point of view or 
time slot add it on the correct position. If it´s proportion function add it to the `types` variable, as example add `c(4,5)` to calculate it over login type 4&5.
If the extracted feature should not be normalized don´t add it to the start or end.
   ```sh
   feature_extraction<-function(...){
      ...
      eature_function<-append(feature_function,NEW_FUNCTION)
      feature_namens<-append(feature_namens,"NAME_OF_NEW_FUNCTION") 
      ...
}
   ```

## Third step

Manipulate the following function, if it should not be normalized or not be included in calculate the means.
   ```sh
   calc_means<-function(features,view,cores){
     ...
     features_without_factors<-select(features,!one_of(c("Identifier","User","Tag","Wochentag","Stunde","NAME_OF_NEW_FUNCTION")))
     ...
   }
   ```
Increment it:
   ```sh
   group_up<-function(...){
     ...
     features[,3+`1`:(ncol(features)-1)]<-normalize_min_max(features[,3+`1`:(ncol(features)-1)],min_max)
     ...
   }
   ```
If it should not be included in the plots:
   ```sh
   visualization_results<-function(...){
     ...
     not_included<-c(...,"NAME_OF_NEW_FUNCTION")
     ...
   }
   ```