#!/usr/bin/Rscript --vanilla
#https://www.r-bloggers.com/2019/11/r-scripts-as-command-line-tools/

# Modul:            Praxis-/Bachelorprojekt
# Thema:            Detect Malicious Login Events
# Autorenschaft:    Richard Mey <richard.mey@syss.de>
# Stand:            16.06.2021

###############
# Bemerkungen #
###############

#Laufzeit ist abhängig von:
#   Anzahl Events im gewählten Zeitraum
#   Größe des Gewählten Zeitraums
#   Abhängig von der Perspektive wie viele Nutzer/Hosts/Quellen enthalten sind
#   Verwendeter ML Methode

#####################
# Kommandoargumente #
#####################

#Laden der Argumente aus der Kommandozeile
args <- commandArgs()

#########
# Setup #
#########

#Legt den path zu den Librarys fest
.libPaths("~/.R")
#Funktion zum installieren/laden aller nötigen Pakete
load_packages<-function(){
  #Dowloadadresse
  repos <- "https://cran.r-project.org/"
  
  ##Installieren der Pakete
  #https://stackoverflow.com/questions/9341635/check-for-installed-packages-before-running-install-packages
  packages <- c("tidyr","dplyr","ggplot2","tools","lubridate","doParallel","reshape2","scales","FactoMineR","factoextra","R.utils","reticulate","RColorBrewer","fmsb","BBmisc","ranger","caret","e1071","clue")
  suppressMessages(install.packages(setdiff(packages, rownames(installed.packages())),repos=repos,quiet = T))
  
  
  #Laden der Pakete
  suppressMessages(library(tidyr))
  suppressMessages(library(tools))
  suppressMessages(library(dplyr))
  suppressMessages(library(ggplot2))
  suppressMessages(library(lubridate,quietly=T,mask.ok = F))
  suppressMessages(library(hms))
  suppressMessages(library(doParallel))
  suppressMessages(library(reshape2))
  suppressMessages(library(scales))
  suppressMessages(library(R.utils))
  suppressMessages(library(reticulate))
  suppressMessages(library(RColorBrewer))
  suppressMessages(library(fmsb))
  suppressMessages(library(BBmisc))
  suppressMessages(library(ranger))
  suppressMessages(library(caret))
  suppressMessages(library(e1071))
  suppressMessages(library(clue))
  
  
  #Options
  options(lubridate.week.start=1) #Wochentag beginnt Montag
  options("scipen" = 10) #Große Zahlen werden vollständig dargestellt
  #Sys.timezone()
  Sys.setenv(TZ='UTC')
}

#Dadurch das innerhalb des setups das Script als Linkdatei verfügbar gemacht wird, muss der Vollständige path zu dessem Order ermittelt werden
location_script<-function(file){
  #Extrahieren des pathes zum Ort wo sich die Link Datei befindet
  file_loc<-sub("[^/]*$","",sub("--file=","",file[grep("--file=.*",file)]))
  if(substring(file_loc,1,1)=="."){
    path_exec<-system("pwd",intern=T)
    link_path<-paste(path_exec,substring(file_loc,2),sep="")
  }else{
    link_path<-substring(file_loc,2)
  }
  #Extrahieren des Realtiven pathes von der Link Datei zum Orginal
  relativ_path<-Sys.readlink(paste("/",link_path,"FindMaliciousEvents",sep=""))
  #Zusammenfügen beider Informationen
  #absolute_path<-paste("/",sub("\\.local/bin/","",link_path),sub("\\.\\./\\.\\./","",sub("FindMaliciousEvents.R$","",relativ_path)),sep="")
  absolute_path<-paste(getAbsolutePath.default(sub("FindMaliciousEvents.R$","",relativ_path),workDirectory = paste("/",link_path,sep="")),"/",sep="")
  return(absolute_path)
}

#read_in der Raw Daten
read_in<-function(path,Output_path){
  #Da R die Datein in den memory ablegt und es bei zu großen Datein zu einem Crash führt, muss entschieden werden ob die Datei getrennt oder vollständig eingelesen wird
  #Auslesen des freien memorys
  mem<-system('free -m',intern=T)
  mem<-strsplit(mem," ")
  mem<-as.numeric(tail(mem[[2]],n=1))

  #Auslesen der Dateigröße
  size<-as.numeric(file.info(path)$size)

  #Wenn das File keine csv ist oder nicht existiert wird das Programm abgebrochen
    if(file_ext(path)=="csv"){
      #Wenn keine Rechte bestehen die Datei auszulesen, wird das Programm abgebrochen
      if(file.access(path,2)==-1){
        stop("Enter a file for which you got the rights to read.",.call=F)
      }
      
      #Wenn die Rohdatei mind. 40% des Memorys belegn würde, wird die Datei teilweise eingelesen
      if(size>=mem*0.5){
          cat("The specified file is too large, hence the read-in/ preprocessing/ feature extraction will be splited. This process might take more time.",fill=2)
          split<-T
          #Damit die Features vollständig bleiben, wird die Orginal Datei nach der Zeit sortiert
          system(paste("sort -k3 -t, ",path, " >> ", Output_path,"time_sort.csv",sep=""))
          return(split)
        }else{
          #Wenn die Datei kleiner als 40% des freien Memorys ist wird die Datei eingelesen
          tryCatch(expr={
            data<-read.csv(path,colClasses = c("integer","numeric","POSIXct","numeric","numeric","numeric","integer","integer"),header = F)
          }, error=function(e){
            stop("Provide a valid, non-empty file and in accordance with the format: Int,Num,Date,Num,Num,Num,Int,Int.",.call=F)
          },warning = function(w){
            stop("The file needs the following columns: Event_ID,Host,Time,Logon_ID,User,Source,Source Port,Logon Typ.",.call=F)
          })
          
          #Wenn die Datei weniger als 1000 Einträge besitzt, wird das Programm abgebrochen
          if(nrow(data)<1000){
            stop("The file contains fewer then 1000 rows. You should use one with more.",.call = F)
          }
          
          #Bennen der Spalten und entfernen aller Events die nicht 4624 entsprechen
          colnames(data)<-c("Event_ID","Host","Time","Logon_ID","User","Source","Source_Port","Logon_Type")#ActivityID oder LogonGUID
          data<-data[(data$Event_ID==4624),]
          #data<-transform(data,Time=as.POSIXct(Time, format = "%Y-%m-%d %H:%M:%S"))
          return(data)
        }
      
    }else{
      stop("The specified file needs to match with one of the acceptable file formats (csv)",.call=F)
    }
  
}

#Falls die Datei zu Groß ist wird diese in teile geteilt
parted_read_in<-function(path,row_multi,back){
  tryCatch(expr = {
    #read_in von x rows und überspringe die vorher bearbeiteten
    data_new<-read.csv(paste(path,"time_sort.csv",sep=""),nrows = 10000000,skip=(row_multi*10000000)-back,colClasses = c("integer","numeric","POSIXct","numeric","numeric","numeric","integer","integer"),header = F)
    colnames(data_new)<-c("Event_ID","Host","Time","Logon_ID","User","Source","Source_Port","Logon_Type")#ActivityID oder LogonGUID
    data_new<-data_new[(data_new$Event_ID==4624),]
    return(data_new)
  }, error = function(e){
    if(row_multi==0){
      stop("Provide a valid, non-empty file and in accordance with the format: Int,Num,Date,Num,Num,Num,Int,Int.",.call=F)
    }else{
      finished<-T
      return(finished) 
    }
  }, warning = function(w){
    stop("The file needs the following columns: Event_ID,Host,Time,Logon_ID,User,Source,Source Port,Logon Typ.",.call=F)
  })
}

#Falls die Option -e angeben wurde können die Features, falls schon welche mit dem Programm extrahiert wurden, eingelesen werden 
features_read_in<-function(path){
  if(file_ext(path)=="csv"){
    if(file.access(path,2)==-1){
      stop("Enter a file for which you got the rights to read.",.call=F)
    }
      tryCatch(expr = {
        features<-read.csv(path,row.names = 1)
        return(features)
      }, error = function(e){
        stop("Provide a valid, non-empty file.",.call=F)
      }, warning = function(w){
      })
    
  }else{
    stop("The specified file needs to match with one of the acceptable file formats (csv)",.call=F)
  }
}

#Um redudante/unötigte Daten zu vermeiden, werden alle Nutzer, welche einer ganzen Zahl <=10000 entsprechen gelöscht
#anschließend werden Duplikate gelöscht
preprocessing<-function(data){
  data<-data[!(data$User %in% c(0:10000)),]
  data<-data%>% distinct(Event_ID,User,Host,Time,Source,Source_Port,Logon_Type)
  return(data)
}

#Extraktion der Features
feature_extraction<-function(data,parsed_arguments,split=F){
  
  view<-parsed_arguments$view
  startdate<-parsed_arguments$startdate
  enddate<-parsed_arguments$enddate
  cores<-parsed_arguments$cores
  time_bin_size<-parsed_arguments$time_bin_size
  
  
  functionset<-build_functionset_extraction(parsed_arguments)
  feature_function<-functionset$feature_function
  feature_namens<-functionset$feature_namens
  Event_Typ<-functionset$Event_Typ
  zeitfenster<-functionset$zeitfenster
  
  #Damit der Prozess der Verarbeitung schneller geht wird ein Cluster mit der gegebene Anzahl erstellt
  cl <- makeCluster(cores)
  registerDoParallel(cl)
  
  features<-data.frame()
  #Im Falle aus der Source view müssen die NA Values entfernt werden
  if(view==5){
    data<-data[(is.na(data$Source)!=T),]
  }
  
  cat("Please magnify the window big enough to present the progress bar completly.",fill=2)
  
  #Anlegen eines Fortschrittsbalken, dieser entspricht der Menge an zu bearbeitenden Daten
  rows<-nrow(data[(data$Time >=(as.Date(startdate)) & (data$Time <(as.Date(enddate)))),])
  progress<-txtProgressBar(min=0, max=rows,width = 100,style = 3, char="=", file=stderr(),title="Feature extraction:")
  processed<-0
  i<-0
  
  #Durchäuft anschlißend abhängig von der Zeiteinheit jeden Tag/Stunde bis zur Abbruchbedingung
  repeat{
    #Extrahiert alle Daten in dem Zeitraum
    window<-data[(data$Time >=(as_datetime(startdate) %m+% zeitfenster(i)) & (data$Time <(as_datetime(startdate)%m+% zeitfenster(i+1+time_bin_size)))),]
    #Falls es leer ist ->überspringe
    if(nrow(window)>0){
      #Extrahiert je nach Scihtweise und duplikatslos die Nutzer/Hosts/Quell-IPs
      iter<- distinct(window,window[[view]])
      #Durchläuft anschließend die Liste in parallelister Form für jeden Nutzer/Host/Quell-IP
      ergebnisse<-foreach(j=1:length(iter[,1]),.packages = c("lubridate","dplyr","hms","R.utils"),.combine = rbind) %dopar%{
        #Extrahiert die Sichtdaten
        data_user<-window[(window[,view]==iter[j,1]),]
        ergebnis<-data.frame()
        #Wendet die Funktionen für die Featureextraktion an
        for(k in 1:length(feature_function)){
          ergebnis[1,k]<-doCall(feature_function[[k]],args=list(data_user=data_user,view=view,startdate=startdate,i=i,Event_Typ=Event_Typ[[k]]),.ignoreUnusedArgs=T)
        }
        return(ergebnis)
      }
      #Fügt das Ergebnisses jedes Durchlaufs hinzu
      features<-rbind(features,ergebnisse)
      
      #Erhöht die bereits durch itertriten Datensätze & gibt es aus
      processed<-processed+nrow(window)
      setTxtProgressBar(progress,processed,title="Feature extraction:") 
      flush.console()
    }
    
    #Abbruchbedingung
    if((as_datetime(startdate)%m+% zeitfenster(i+1+time_bin_size))>=as_datetime(enddate)){
      break
    }
    i<-i+1+time_bin_size
  }
  #Stoppen des Clusters
  stopCluster(cl)
  close(progress)
  
  #Gibt den Features die Namen
  colnames(features)<-feature_namens
  
  #Wenn die Daten nicht gesplittet vorliegen, Cluster diese
  if(split!=T && parsed_arguments$group==T){
    features<-group_up(features,view,parsed_arguments$time_bin,cores,load_model=parsed_arguments$load_model,model_path=parsed_arguments$model_path,save_model=parsed_arguments$save_model,path=parsed_arguments$path)
  }

  return(features)
}

#Zuerst werden alle Funktionen zur Features Extraktion definiert
Identifier<-function(data_user,view,...){
  return(data_user[1,view])
}

Wochentag<-function(startdate,i,...){
  return(wday(ymd(as.Date(startdate) %m+% days(i)),week_start = getOption("lubridate.week.start",1)))
}

Stunde<-function(i,...){
  return(as_hms(((i)%%24)*60*60) )
}

Tag<-function(startdate,i,...){
  return(as_date((as.Date(startdate) %m+% hours((i)))))
}

Tag_2<-function(startdate,i,...){
  return(as_date((as.Date(startdate) %m+% days((i)))))
}

Anzahl_Events<-function(data_user,...){
  return(nrow(data_user))
}


Anteil_Event<-function(data_user,Event_Typ,...){
  return(nrow(data_user[(data_user$Logon_Type %in% Event_Typ),])/nrow(data_user))
}

Events_per_Second<-function(data_user,...){
  anzahl<-nrow(data_user)
  if(anzahl==1){
    return(0)
  }else if(as.numeric(difftime(max(data_user[,3]),min(data_user[,3]),units = "secs"))==0){
    return(1)
  }else{
    return(anzahl/as.numeric(difftime(max(data_user$Time),min(data_user$Time),units = "secs")))
  }
}

Hosts_per_X<-function(data_user,view,...){
  return((data_user%>% distinct(Host,X=.[[view]]) %>%group_by(X)%>% summarise(n()))$`n()`)
}

Sources_per_X<-function(data_user,view,...){
  return((data_user%>% distinct(Source,X=.[[view]]) %>%group_by(X)%>% summarise(n()))$`n()`)
}

Users_per_X<-function(data_user,view,...){
  return((data_user%>% distinct(User,X=.[[view]]) %>%group_by(X)%>% summarise(n()))$`n()`)
}

build_functionset_extraction<-function(parsed_arguments){
  
  time_bin<-parsed_arguments$time_bin
  view<-parsed_arguments$view
  days_instead<-parsed_arguments$days_instead
  
  #Definition, welche Funktionen zur Feature Extraktion dann genutzt werden & welche Namen sie besitzen
  #Dies dient dazu eine gewisse modulartät in den verschiedene Featuren zu schaffen
  feature_function<-c()
  feature_namens<-c()
  
  #Es wird stehts ein Identifiziere mit genutzt
  feature_function<-append(feature_function,Identifier)
  feature_namens<-append(feature_namens,"Identifier")

  #Außerdem wird stehts mindestens ein zeit Format genutzt
  if(time_bin=="d"){
    if(days_instead){
      feature_function<-append(feature_function,Tag_2)
      feature_namens<-append(feature_namens,"Tag")
    }else{
      feature_function<-append(feature_function,Wochentag)
      feature_namens<-append(feature_namens,"Wochentag") 
    }
    zeitfenster<-days
  }else if(time_bin=="h"){
    feature_function<-append(feature_function,Stunde)
    feature_namens<-append(feature_namens,"Stunde")
    zeitfenster<-hours
  }else{
    feature_function<-append(feature_function,Tag)
    feature_function<-append(feature_function,Stunde)
    feature_namens<-append(feature_namens,c("Tag","Stunde"))
    zeitfenster<-hours
  }
  
  
  #Anschließend werden die normalen Zähl Features eingeschlossen
  feature_function<-append(feature_function,Anzahl_Events)
  feature_namens<-append(feature_namens,"Anzahl_Events")
  
  types<-list(2,3,9,10,c(11,12))
  start_typ<-length(feature_function)+1
  for(z in 1:length(types)){
    feature_function<-append(feature_function,Anteil_Event)
    feature_namens<-append(feature_namens,paste("Anteil",paste(as.character(unlist(types[[z]])),collapse="_"),sep = "_"))
  }
  end_typ<-start_typ+length(types)-1
  feature_function<-append(feature_function,Events_per_Second)
  feature_namens<-append(feature_namens,"Events_per_Second")
  
  #Anhand der Sichtweise werden dann die Sichtweise Features hinzugefügt, 2=view Host, 4= view Nutzer, 5= view Quell-IP
  if(view==2){
    feature_function<-append(feature_function,Users_per_X)
    feature_function<-append(feature_function,Sources_per_X)
    feature_namens<-append(feature_namens,c("Users_per_Host","Sources_per_Host"))
  }else if(view==4){
    feature_function<-append(feature_function,Hosts_per_X)
    feature_function<-append(feature_function,Sources_per_X)
    feature_namens<-append(feature_namens,c("Hosts_per_User","Sources_per_User"))
  }else{
    feature_function<-append(feature_function,Users_per_X)
    feature_function<-append(feature_function,Hosts_per_X)
    feature_namens<-append(feature_namens,c("Users_per_Source","Hosts_per_Source"))
  }
  
  #Aufgrund das bei der späteren Ausführung immer die selben Variablen übergeben werden müssen, aber eine modulare abhängigkeit besteht
  #wird eine liste identisch lang zu der Anzahl an Featuren erstellt mit den Informatione zu den Untersuchenden LoginTypen verwendet
  Event_Typ<-rep(list(0),length(feature_function))
  for(z in 1:(end_typ-start_typ+1)-1){
    Event_Typ[[(start_typ+z)]]<-types[[z+1]]
  }
  
  return(list(feature_function=feature_function,feature_namens=feature_namens,Event_Typ=Event_Typ,zeitfenster=zeitfenster))
}

#Berechnen der Mittelwertdaten
calc_means<-function(features,view,cores){
  
  #ignoriere Warnungen
  options(warn = -1)
  #Schließe die Features aus bei den es nicht sinnvoll wäre (Kennung/Zeit)
  tryCatch(expr = {
    features_without_factors<-select(features,!one_of(c("Identifier","User","Tag","Wochentag","Stunde")))
  })
  
  #Extrahiere die Kennungen ohne duplikate
  iter<- distinct(features,Identifier)
  
  #Ertselle ein Cluster
  cl <- makeCluster(cores)
  registerDoParallel(cl)
  
  #Iterriere durch die Nutzer/Hosts/Quell-IPs durch und bilde pro Nutzer pro Feature den Mittelwert
  means<-foreach(j=1:length(iter[,1]),.packages = c("lubridate","dplyr"),.combine = rbind) %dopar%{
    data_iter<-features_without_factors[(features$Identifier==iter[j,1]),]
    ergebnis<-data.frame()
    for(j in 1:ncol(features_without_factors)){
      ergebnis[1,j]<-mean(data_iter[,j])
    }
    return(ergebnis)
  }
  stopCluster(cl)
  
  #Bennene die Mittelwert Features
  colnames(means)<-colnames(features_without_factors)
  
  #Gebe die Liste der Sichtweise+ Mittelwert features zurück
  return(list(iter,means))
}

#Clustern
clustern<-function(iter_means,features,k,label,load_model,model_path,save_model,path){
  
  if(load_model){
    km.res<-readRDS(file = paste(model_path,"cluster.rds",sep=""))
    groups<-data.frame(Groups=as.numeric(cl_predict(km.res,iter_means[[2]],type="class_id")))
  }else{
    #Setze ein seed zur reproduzierbarkeit und Cluster anschlißend die Mittelwertdaten 
    set.seed(123)
    km.res <- kmeans(iter_means[[2]], k,algorithm = "Hartigan-Wong", nstart = 100)
    
    #Extrahiere die Clusternummern aus dem Ergebniss des clusterns
    groups<-data.frame(Groups=km.res[["cluster"]]) 
  }
  
  if(save_model){
    saveRDS(km.res,paste(path,"model/cluster.rds",sep = ""))
  }
  
  #Wenn es als Feature verwendet werden soll nutze Variante 1 anssonsten als Label Var 2
  if(label==F){
    #Füge die Kennung & Clusternummer zusammen
    iter<-data.frame(Identifier=iter_means[[1]],Gruppe=as.factor(groups[,1]))
    
    #Joine die Features& das vorhergehende um die Clusternummern der jeweiligen Sichtweise hinzufügen
    features<-left_join(features,iter,by="Identifier")
    #Erstelle einzigartige Kennungen=Zeilennamen (z.B. Nutzer1234.X) um sie später wieder identifizieren zu können
    uniq_rownames<-c(make.names(features[,1],unique = T))
    rownames(features)<-uniq_rownames
    features<-features[,-which(names(features) %in% c("Identifier"))]
    features<-features%>%rename(Identifier=Gruppe)
    return(features)
  }else{
    #Falls es nur als Label verwendet werden soll, reicht es aus die Mittelwertdaten+Gruppe zusammenzufügen
    means_label<-data.frame(iter_means[[2]],Gruppe=as.factor(groups[,1]))
    return(means_label)
  }

}

min_max_calc<-function(features,time_bin){
  if(time_bin=="dh"){
    start<-3
  }else{
    start<-2
  }
  min_max<-data.frame()
  j<-1
  for(i in 1:ncol(features[,start:(ncol(features)-1)])+start-1){
    min_max[j,1]<-min(features[,i])
    min_max[j,2]<-max(features[,i])
    j<-j+1
  }
  return(min_max)
}

min_max_calc_2<-function(min_max,min_max_new){
  for(i in 1:ncol(min_max)){
    min_max[i,1]<-min(min_max[i,1],min_max_new[i,1])
    min_max[i,2]<-max(min_max[i,2],min_max_new[i,2])
  }
  return(min_max)
}

normalize_2<-function(features,min,max){
  min_max_normalize<-function(features,min,max){
    return((features-min)/(max-min))
  }
  return(sapply(features,min_max_normalize,min=min,max=max))
}


normalize_min_max<-function(features,min_max){
  for(i in 1:ncol(features)){
    features[,i]<-normalize_2(features[,i],min=min_max[i], max=min_max[ncol(features)+1])
  }
  return(features)
}

#Übergreifende Funktion für die Bildung der Mittelwerte+Clustern
group_up<-function(features,view,time_bin,cores,label=F,load_model,model_path,save_model,path){
  #Berechnung Mittelwerte
  iter_means<-calc_means(features,view,cores)
  #Cluster zuweisung
  features<-clustern(iter_means,features,13,label,load_model,model_path,save_model,path)
  
  if(save_model && label==F){
    min_max<-min_max_calc(features,time_bin)
    saveRDS(min_max,paste(path,"model/min_max.rds",sep=""))
  }
  
  #Führe eine 0-1 Normalisierung durch, falls es nicht als Label verwendet werden soll -> sorgt für Beschleunigung der Lerner
  if(label==F){
    if(load_model){
      min_max<-readRDS(paste(model_path,"min_max.rds",sep=""))
      min_max_new<-min_max_calc(features,time_bin)
      min_max<-as.numeric(unlist(min_max_calc_2(min_max,min_max_new)))
      if(time_bin=="dh"){
        features[,3:(ncol(features)-1)]<-normalize_min_max(features[,3:(ncol(features)-1)],min_max)
      }else{
        features[,2:(ncol(features)-1)]<-normalize_min_max(features[,2:(ncol(features)-1)],min_max)
      }
    }else{
      if(time_bin=="dh"){
        features[,3:(ncol(features)-1)]<-normalize(features[,3:(ncol(features)-1)],method="range",range = c(0,1))
      }else{
        features[,2:(ncol(features)-1)]<-normalize(features[,2:(ncol(features)-1)],method="range",range = c(0,1))
      }
    }
  }
  
  return(features)
}

#Prüft ob Python 3 installiert ist, falls ja aktiviert es ein demenstprechendes vorher aktiviertes virtuell envirmoment
setup_python<-function(path){
  tryCatch(expr={
    use_python(as.character(system("which python3",intern = T)))
  },error=function(e){
    stop("Python 3 is not installed.",.call=F)
  })
  use_virtualenv(paste(path,"maliciousevents",sep=""))
}

#Führt das Python Funktion mit dem Isolationsbaum aus
isolationforest<-function(Input_path,Output_path,cores,rank,load_model,save_model,model_path){
  source_python(paste(Input_path,"ml/IsolationForest_Anwendung.py",sep=""))
  isolationforest_exec(Input_path,Output_path,as.integer(cores),rank,load_model,save_model,model_path)
}

#Führt die Python Funktion mit dem kNN aus
kNN<-function(Input_path,Output_path,cores,rank,load_model,save_model,model_path){
  source_python(paste(Input_path,"ml/kNN_Anwendung.py",sep=""))
  knn_exec(Input_path,Output_path,as.integer(cores),rank,load_model,save_model,model_path)
}

#Führt die Python Funktion mit dem DAGMM aus
dagmm<-function(Input_path,Output_path,rank,load_model,save_model,model_path){
  source_python(paste(Input_path,"ml/DAGMM_Anwendung.py",sep=""))
  dagmm_exec(Input_path,Output_path,rank,load_model,save_model,model_path)
}

#Nutzt einen Random Forest um Nutzer/hosts/Quell-IPs die viele Gruppen besuchen als ungewöhnlich einzustuffen
randomforest<-function(features,view,time_bin,cores,path,load_model,model_path,save_model){
  #Clustert die Daten und gibt die Mittelwertdaten+ die Clusternummer als Label zurück
  means_label<-group_up(features,view,time_bin,cores,label = T,load_model,model_path,save_model,path)
  
  if(load_model){
    model<-readRDS(paste(model_path,"model.rds",sep=""))
    tryCatch(
      expr = {
        model_type<-attr(model$forest,"class")
        if(model_type!="ranger.forest"){
          stop("Use the correct model on load with the correct machine learning option.",.call=F)
        }
      }, error = function(e){
        stop("Use the correct model on load with the correct machine learning option.",.call=F)
      }
    )
    if(any((model[["forest"]][["independent.variable.names"]] %in% colnames(means_label))==F)){
      cat("Your given model contains a feature that is note included in your extracted feature set.",fill = 1)
    }
  }else{
    #Teilt die Mittelwertdaren in Train- und Testdaten
    train<-means_label[sample(1:nrow(means_label),nrow(means_label)*0.7),]
    test<-means_label[!(rownames(means_label) %in% rownames(train)),]
    
    #Erstellt ein Hyperparamter Netz um die "optimale" Hypperparamter zu finden
    hyper_grid <- expand.grid(
      mtry       = seq(2, ncol(means_label)-1, by = 1),
      node_size  = seq(3, 9, by = 2),
      sampe_size = c(.55, .632, .70, .80),
      max_deph   = seq(5,14, by=2),
      OOB_RMSE   = 0,
      pred_test  = 0
    )
    
    #Iteriert durch dieses Netz & berechnet die Accuracy
    for(i in 1:nrow(hyper_grid)) {
      
      # train model
      model <- ranger(
        formula         = Gruppe ~ ., 
        data            = train, 
        num.trees       = 500,
        mtry            = hyper_grid$mtry[i],
        min.node.size   = hyper_grid$node_size[i],
        sample.fraction = hyper_grid$sampe_size[i],
        max.depth       = hyper_grid$max_deph[i],
        seed            = 123
      )
      
      # add OOB error to grid
      hyper_grid$OOB_RMSE[i] <- sqrt(model$prediction.error)
      preds <- predict(model, data=test,type="response")
      conf<-confusionMatrix(preds$predictions, test$Gruppe)
      hyper_grid$pred_test[i]<-as.numeric(conf$overall[1])
    }
    
    #Sortiert das Netz nach der Accuracy
    hyper_grid<-hyper_grid[order(hyper_grid$pred_test,decreasing = T),]
    
    #Ertsellt und trainiert anschließend das endültige modell mit den besten Hyperparametern
    model <- ranger(
      formula         = Gruppe ~ ., 
      data            = means_label, 
      num.trees       = 500,
      mtry            = hyper_grid$mtry[1],
      min.node.size   = hyper_grid$node_size[1],
      sample.fraction = hyper_grid$sampe_size[1],
      max.depth       = hyper_grid$max_deph[1],
      seed            = 123
    ) 
  }
  
  if(save_model){
    saveRDS(model,paste(path,"model/","model.rds",sep=""))
  }
  
  #Prediction auf den echten Feature Datensatz
  tryCatch(
    expr = {
      preds <- predict(model, data=features[,c(colnames(means_label[-c(ncol(means_label))]))],type="response")
    }, error = function(e){
      stop("The features of the data should be the same like the model features.",.call=F)
    }
  )
  #Neues DataFrame mit kennung+Gruppe
  Identifier_Gruppe<-data.frame(Identifier=features[,1],Gruppe=as.factor(preds$predictions))
  
  #Zählt wie viele unterschiedliche Gruppen besucht werden und sortiert es absteigend
  result <- Identifier_Gruppe %>% distinct(Identifier,Gruppe) %>% group_by(Identifier) %>% summarise(n())
  result <- as.data.frame(result[order(result$`n()`,decreasing = T),])
  #Schreibt das Ergebniss nieder
  write.csv(result,paste(path,"Ergebnisse.csv",sep=""),row.names = F)
}

#Zur Visualierung werden Radarplots der erkannten Anomalien erstellt+ausgeben
visualization_results<-function(features,Output_path,NOT_RF,rank){
  
  ergebnisse<-read.csv(paste(Output_path,"Ergebnisse.csv",sep=""))
  
  if("Stunde" %in% colnames(features)){
    features["Stunde"]<-as.numeric(seconds(as_hms(sapply(features["Stunde"],as.character))))
    ergebnisse["Stunde"]<-as.numeric(seconds(as_hms(sapply(ergebnisse["Stunde"],as.character))))
  }
  
  identifier<-data.frame(Identifier=sub("^X","",sub("\\.[0-9]*$","",ergebnisse[,1])))
  iter<-distinct(identifier,Identifier=Identifier)
  if(NOT_RF==F || rank ==T){
    iter<-iter %>% slice(1:50)
  }
  
  Output_path<-paste(Output_path,"Radarplots/",sep="")
  dir.create(Output_path)
  
  palette <- colorRampPalette(colors=c("#000000", "#FFFFF0"))
  palette_outsider<-colorRampPalette(c("red","purple"))
  par(mar = c(1, 1, 2, 1))
  par(oma=c(0,0,0,0))
  tryCatch(
    expr = {
      for(i in 1:nrow(iter)){
        if(NOT_RF==T){
          outsider<-grep(paste("^X",iter[i,1],"(\\.[0-9]+$){0,1}",sep=""),ergebnisse[,1],value=T)
          insider<-grep(paste("^X",iter[i,1],"(\\.[0-9]+$){0,1}",sep=""),rownames(features),value=T) 
          if(length(insider)>50){
            insider<-sample(insider,50)
          }
          cols <- character(length(insider))
        }else{
          insider<-features[(features$Identifier==iter[i,1]),]
          outsider<-""
          if(nrow(insider)>50){
            insider<-insider[sample(1:nrow(insider),50),]
          }
          cols <- character(nrow(insider))
        }
        
        if(NOT_RF){
          insider<-subset(insider,!(insider %in% outsider))
        }
        
        if(NOT_RF==T){
          cols[1:(length(cols)-length(outsider))]<-palette((length(cols)-length(outsider)))
          cols[(length(cols)-length(outsider)+1):length(cols)]<-palette_outsider(length(outsider)) 
          not_included<-c("User","Identifier","Tag")
          plot_data<-rbind(select(features[insider,],!one_of(not_included)),select(features[outsider,],!one_of(not_included)))
        }else{
          cols<-palette(nrow(insider))
          plot_data<-insider[-c(1)]
        }
        
        
        cols_in <- alpha(cols,0.2)
        
        jpeg(paste(Output_path,i,"_",iter[i,1],".jpg",sep=""), width = 1900, height = 1900,quality=100,pointsize = 40,res=120)
        radarchart(plot_data,maxmin = F,axistype = 1,pcol=cols,pfcol=cols_in, plwd=1 , plty=2, cglty=1,cglwd=0.8, cglcol="#466D3A",vlcex=0.8,axislabcol="#00008B" )
        dev.off()  
      }
    }, error = function(e){
      cat("No Radarplots generated, because there is just one Feature per view to be plotted.",fill=1)
    }
  )

}

###Datenanlyse Funktionen
daten_analyse<-function(data,path){
  allgemeine_infos(data,path)
  logintypen(data,path)
  timeline<-timeline_month(data,path)
  borders<-calc_borders(timeline)
  timeline_day(data,path,borders[[1]],borders[[2]])
  return(borders)
}

logintypen<-function(data,path){
  logontype<-data.frame()
  for(i in 1:14-1){
    logontype_x<-data[(data$Logon_Type==i),]
    logontype[i+1,1]<-i
    logontype[i+1,2]<-length(logontype_x[,1])
  }
  logontype_plot<-ggplot(data=logontype,aes(x=logontype[,1],y=logontype[,2])) +
    geom_bar(stat="identity")+
    xlab("Logon Type") + ylab("Anzahl")
  
  ggsave(paste(path,"Login_Typen.png",sep=""),logontype_plot,width = 10,dpi=300,limitsize = F)
}

allgemeine_infos<-function(data,path){
  infos<-c()
  infos[1]<-paste("Existing Well known Source Ports:",paste(as.character(c(data[(data$Source_Port %in% c(1:1023) & is.na(data$Source_Port)!=T),"Source_Port"])),collapse=", "))
  infos[2]<-paste("Number of Hosts:",nrow(group_by(data,data$Host) %>% summarise(n())))
  infos[3]<-paste("Number of Users:",nrow(group_by(data,data$User) %>% summarise(n())))
  infos[4]<-paste("Number of Source-IPs:",nrow(group_by(data,data$Source) %>% summarise(n())))
  infos[5]<-paste("Smallest date of the data:",min(data$Time))
  infos[6]<-paste("Newest date:",max(data$Time))
  write.table(infos,file=paste(path,"Allgemeine_Infos.txt",sep=""),row.names = F,col.names = F)
}

timeline_month<-function(data,path=0){
  i<-0
  min_date<-as.Date(paste(year(min(data$Time)),month(min(data$Time)),"01",sep="-"))
  max_date<-as.Date(paste(year(max(data$Time)),month(max(data$Time)),"01",sep="-"))
  timeline<-data.frame()
  repeat{
    timeline[i+1,1]<-(min_date%m+% months(i))
    timeline[i+1,2]<-nrow(data[(data$Time >=(min_date%m+% months(i)) & (data$Time <(min_date%m+% months(i+1)))),])
    
    if((min_date%m+% months(i))==max_date){
      break
    }
    i<-i+1
  }
  colnames(timeline)<-c("Time","Anzahl")
  
  if(path!=0){
    timeplot<-ggplot(timeline,aes(x=Time,y=Anzahl))+
      geom_area(fill="#69b3a2",alpha=0.5)+
      geom_line()
    
    ggsave(paste(path,"Volle_Zeitreihe_in_Monaten.png",sep=""),timeplot,width = 50,dpi=300,limitsize = F)
  }
  
  return(timeline)
}

calc_borders<-function(timeline){
  timeline[,3]<-scale(timeline[,2])
  border<-as.numeric(quantile(timeline[,3],(0.90+nrow(timeline)*0.00019)))
  left<-timeline[timeline[,3]>border,]
  return(list(left[1,1],as.Date(left[nrow(left),1]) %m+%months(1)))
}

timeline_day<-function(data,path,startdate,enddate){
  i<-0
  timeline<-data.frame()
  repeat{
    timeline[i+1,1]<-(as.Date(startdate)%m+% days(i))
    timeline[i+1,2]<-nrow(data[(data$Time >=(as.Date(startdate)%m+% days(i)) & (data$Time <(as.Date(startdate)%m+% days(i+1)))),])
    
    if((as.Date(startdate)%m+% days(i))==as.Date(enddate)){
      break
    }
    i<-i+1
  }
  
  colnames(timeline)<-c("Time","Anzahl")
  
  timeplot<-ggplot(timeline,aes(x=Time,y=Anzahl))+
    geom_area(fill="#69b3a2",alpha=0.5)+
    geom_line()
  
  ggsave(paste(path,"Quantil_Zeitreihe_Tage.png",sep=""),timeplot,width = 50,dpi=300,limitsize = F)
}

#################
# Help Funktion #
#################

#Falls die Option --help Angeben wird, wird folgender Text auf der Konsole ausgegeben

help_output<-function(){
  cat("Usage: FindMaliciousEvents [file] [dir] [--options]",
        "Currently supported file formats are: csv. The File needs the following construction (Event ID, Host, Time, Logon ID, User, Source, Source Port, Logon Type).",
        "Options:",
        "",
        "--help    Help output",
        "-da       Gives overall statictics to given data",
        "-v        Specification of the perspective with the following argument, default is User",
        "          u User   From a users point of view",
        "          h Host   From a hosts point of view",
        "          s Source From a source point of view",
        "-t        Specification of the time slot with the following argument, default is day",
        "          d Day",
        "            d Use days instead of weakdays",
        "          h Hour",
        "          dh Day&Hour",
        "             default is one hour for h&dh, write a number of hours as next argument it to change it",
        "-d        Choose a start- and enddate, default is a quantile",
        "          m Manual establishing",
        "            startdate Y-M-D",
        "            enddate   Y-M-D, is not included",
        "          v Complet span",
        "-e        If you are already got an extracted feature set, you can use it instead of the data file",
        "-m        Choose one of the given machine learning algorithm for evaluation, default is an isolation forest",
        "          IF Isolation forest",
        "          kNN k-nearest-neigbhour",
        "          DAGMM Deep Autoencoding Gausian Mixture Model",
        "          RF Randomforest",
        "-p        Use this to limit your cores to use. The next argument should be the logical count of cores to use, default is cores-1",
        "-r        The output will be a complet ranked list",
        "-s        Save the trained model",
        "-lm       The next argument should be the path to the directory with the trained model information",
        "-n        Plots will not be generated", fill=2)
}

#################
# Main Funktion #
#################

#Hauptfunktion steuert, welche Funktionen aufgerufen werden aufgrund der übergebenen Argumente
main<-function(args){
  # validate_argument(args)
  # parsed_arguments <- parse_arguments(args)
  # extracted_features <- extract_features(parsed_arguments.feature_extraction)
  # anomalies <- anomaly_detection(extracted_features, parsed_arguments.anomaly_detection)
  # if parsed_arguments.should_be_ranked:
  #   ranking <- rank(anomalies)
  #   persist(ranking)
  # else
  #   persist(anomalies)
  
  envr_args<-args[1:grep("--args",args)]
  args<-args[grep("--args",args)+1:length(args)]
  
  if(length(args)==0){
    stop("You need to hand over a dataset.",.call=F)
  }else if(args[1]=="--help"){
    help_output()
  }else if(file.exists(args[1])==F){
    stop("The file needs to exist.",.call=F)
  }else if(dir.exists(args[2])==F){
    stop("The directory needs to exists.",.call=F)
  }else{
    
    if(file.access(as.character(args[2]),c(4,2))==-1){
      stop("Enter a location where you got the sufficient rights (w,r).",.call=F)
    }
    path<-create_new_folder(args)
    load_packages()
    parsed_arguments<-parse_arguments(args,envr_args)
    parsed_arguments$path<-path
    features<-extract_features_main(parsed_arguments)
    anomaly_detection(features,parsed_arguments)
    
    if(parsed_arguments$with_plots){
      visualization_results(features,path,parsed_arguments$group,parsed_arguments$rank) 
    }
    
  }

}


create_new_folder<-function(args){
  tryCatch(expr = {
    path<-paste(as.character(args[2]),"/FindMaliciousEvents_1/",sep="")
    if(dir.exists(path)==F){
      dir.create(path)
    }else{
      dir<-list.dirs(as.character(args[2]),recursive = F,full.names = F)
      dir_ME<-grep("FindMaliciousEvents_[0-9]+",dir)
      path<-paste(as.character(args[2]),"/FindMaliciousEvents_",(max(as.numeric(sub("[^0-9]+","",dir[dir_ME])))+1),"/",sep="")
      dir.create(path)
    }
    return(path)
  }, warning=function(w){
  }, finally = {
  })
}

parse_arguments <- function(args,envr_args){
  parsed_arguments<-list()
  parsed_arguments$data_path<-data_path_argument(args)
  parsed_arguments$statistics<-statistics_argument(args)
  parsed_arguments$view<-view_argument(args)
  ml_and_group<-machine_learning_argument(args)
  parsed_arguments$ml<-ml_and_group$ml
  parsed_arguments$group<-ml_and_group$group
  time_arguments<-time_bin_argument(args)
  parsed_arguments$time_bin<-time_arguments$time_bin
  parsed_arguments$time_bin_size<-time_arguments$time_bin_size
  parsed_arguments$days_instead<-time_arguments$days_instead
  time_window<-time_window_argument(args)
  parsed_arguments$startdate<-time_window$startdate
  parsed_arguments$enddate<-time_window$enddate
  parsed_arguments$completely<-time_window$completely
  parsed_arguments$rank<-rank_argument(args)
  parsed_arguments$cores<-cores_argument(args)
  loaded_model<-load_model_argument(args)
  parsed_arguments$load_model<-loaded_model$load_model
  parsed_arguments$model_path<-loaded_model$model_path
  parsed_arguments$save_model<-save_model_argument(args)
  parsed_arguments$with_plots<-with_plots_argument(args)
  parsed_arguments$extracted_features<-extracted_features_argument(args)
  parsed_arguments$absolute_path<-location_script(envr_args)
  return(parsed_arguments)
}

data_path_argument<-function(args){
  return(as.character(args[1]))
}


statistics_argument<-function(args){
  
  statistics<-F
  
  if(length(grep("-da",as.character(args)))!=0 && grep("-da",as.character(args))>2){
    statistics<-T
  }
  return(statistics)
}

view_argument<-function(args){
  
  view<-4
  
  if(length(grep("-v",as.character(args)))!=0){
    if(length(args[grep("-v",as.character(args))+1])!=1){
      stop("Choose one of the point of views as option (u,h,s)",.call=F)
    }else{
      if(as.character(args[grep("-v",as.character(args))+1])=="u" ||as.character(args[grep("-v",as.character(args))+1])=="h" ||as.character(args[grep("-v",as.character(args))+1])=="s" ){
        if(as.character(args[grep("-v",as.character(args))+1])=="u"){
          view<-4
        }else if(as.character(args[grep("-v",as.character(args))+1])=="h"){
          view<-2
        }else{
          view<-5
        }
      }else{
        stop("Choose one of the valid point of views as option  (u,h,s)",.call=F)
      }
    }
  }
  return(view)
}

machine_learning_argument<-function(args){
  
  ml<-"IF"
  group<-T
  
  if(length(grep("-m",as.character(args)))!=0){
    if(length(args[grep("-m",as.character(args))+1])!=1){
      stop("Choose one of the machine learning options (IF,kNN,RF)",.call=F)
    }else{
      if(as.character(args[grep("-m",as.character(args))+1])=="IF" ||as.character(args[grep("-m",as.character(args))+1])=="kNN" || as.character(args[grep("-m",as.character(args))+1])=="DAGMM" || as.character(args[grep("-m",as.character(args))+1])=="RF"){
        if(as.character(args[grep("-m",as.character(args))+1])=="IF"){
          ml<-"IF"
        }else if(as.character(args[grep("-m",as.character(args))+1])=="kNN"){
          ml<-"kNN"
        }else if(as.character(args[grep("-m",as.character(args))+1])=="DAGMM"){
          ml<-"DAGMM"
        }else{
          ml<-"RF"
          group<-F
        }
      }else{
        stop("Choose one of the valid machine learning options (IF,kNN,RF)",.call=F)
      }
    }
  }
  return(list(ml=ml,group=group))
}

time_bin_argument<-function(args){
  
  time_bin<-"d"
  time_bin_size<-0
  days_instead<-F
  
  if(length(grep("-t",as.character(args)))!=0){
    if(length(args[grep("-t",as.character(args))+1])!=1){
      stop("Choose one of the time slot options (d,h,dh)",.call=F)
    }else{
      if(as.character(args[grep("-t",as.character(args))+1])=="h" ||as.character(args[grep("-t",as.character(args))+1])=="d" ||as.character(args[grep("-t",as.character(args))+1])=="dh"){
        if(as.character(args[grep("-t",as.character(args))+1])=="d"){
          time_bin<-"d"
          if(length(args[grep("-t",as.character(args))+2])!=0){
            if(as.character(args[grep("-t",as.character(args))+2])=="d"){
              days_instead<-T
            }else{
              stop("The only option you can use here is d.",.call=F)
            }
          }
        }else{
          if(as.character(args[grep("-t",as.character(args))+1])=="h"){
            time_bin<-"h" 
          }else{
            time_bin<-"dh"
          }
          
          if(length(args[grep("-t",as.character(args))+2])!=0){
            if(length(grep("^[0-9]*$",as.character(args[grep("-t",as.character(args))+2])))!=0){
              time_bin_size<-as.numeric(args[grep("-t",as.character(args))+2])-1
              if(time_bin_size<0 || time_bin_size >71){
                stop("Please insert a number of hours bigger then 0 and smaller then 73.",.call=F)
              }
            }else{
              stop("Please insert a number behind the hour/day-hour time bin format.",.call=F)
            }
          }else{
          }
        }
      }else{
        stop("Choose one of the valid time slot options (d,h,dh)",.call=F)
      }
    }
  }
  return(list(time_bin=time_bin,time_bin_size=time_bin_size,days_instead=days_instead))
}

rank_argument<-function(args){
  if(length(grep("-r",as.character(args)))!=0){
    rank<-T
  }else{
    rank<-F
  }
  return(rank)
}

time_window_argument<-function(args){
  completely<-F
  if(length(grep("-d",as.character(args)))!=0){
    if(length(args[grep("-d",as.character(args))+1])!=1){
      stop("Choose an option for start- and enddate (m,v)",.call=F)
    }else{
      if(as.character(args[grep("-d",as.character(args))+1])=="m" ||as.character(args[grep("-d",as.character(args))+1])=="v"){
        if(as.character(args[grep("-d",as.character(args))+1])=="m"){
          if(length(args[grep("-d",as.character(args))+2])!=1 && length(args[grep("-d",as.character(args))+3])!=1){
            stop("Hand over a start- and enddate.",.call=F)
          }else{
            tryCatch(expr = {
              startdate<-as_date(args[grep("-d",as.character(args))+2])
              enddate<-as_date(args[grep("-d",as.character(args))+3])
            }, warning = function(w){
              stop("Hand over a valid start- and enddate.",.call=F)
            })
            if(startdate>enddate){
              stop("Your startdate is older then the enddate, change the information.",.call=F)
            }
          }
        }else{
          completely<-T
        }
      }else{
        stop("Choose a valid option for the start- and enddate (m,v).",.call=F)
      }
    }
  }else{
    startdate<-NULL
    enddate<-NULL
  }
  return(list(startdate=startdate,enddate=enddate,completely=completely))
}

cores_argument<-function(args){
  if(length(grep("-p",as.character(args)))!=0){
    if(length(args[grep("-p",as.character(args))+1])!=1){
      stop("Hand over a number of logical processors to use.",.call=F)
    }else{
      tryCatch(expr = {
        cores<-as.numeric(args[grep("-p",as.character(args))+1])
        if(cores>detectCores()){
          stop("You can´t use a bigger number of logicals processors then available.",.call=F)
        }
      },warning=function(w){
        stop("Insert a number of cores, based on your processor.",.call=F)
      })
    }
  }else{
    cores<-detectCores()-1
  }
  return(cores)
}

load_model_argument<-function(args){
  if(length(grep("-lm",as.character(args)))!=0){
    if(length(args[grep("-lm",as.character(args))+1])!=1){
      stop("You need to hand over a path to the directory with the model information.",.call=F)
    }else{
      model_path<-as.character(args[grep("-lm",as.character(args))+1])
      if(dir.exists(model_path)==F){
        stop("You need to hand over an existing model directory.",.call=F)
      }
      if(file.exists(paste(model_path,"cluster.rds",sep=""))==F || (file.exists(paste(model_path,"min_max.rds",sep=""))==F && ml!="RF") || (file.exists(paste(model_path,"model.joblib",sep=""))==F && file.exists(paste(model_path,"model.rds",sep=""))==F && file.exists(paste(model_path,"DAGMM_model.index",sep=""))==F) ){
        stop("Hand over a directory that contains the following content: (min_max.rds), cluster.rds, model.(rds/joblib/index)",.call=F)
      }
      
      if((file.exists(paste(model_path,"model.rds",sep=""))==F && ml=="RF") || (file.exists(paste(model_path,"model.rds",sep=""))==T && (ml=="IF" || ml=="kNN")) || (file.exists(paste(model_path,"DAGMM_model.index",sep=""))==F && ml=="DAGMM")){
        stop("Use the correct model on load with the correct machine learning option.",.call=F)
      }
      load_model<-T
    }
  }else{
    model_path<-""
    load_model<-F
  }
  return(list(load_model=load_model,model_path=model_path))
}

save_model_argument<-function(args){
  if(length(grep("-s",as.character(args)))!=0){
    save_model<-T
    dir.create(paste(path,"model/",sep=""))
  }else{
    save_model<-F
  }
  return(save_model)
}

with_plots_argument<-function(args){
  if(length(grep("-n",as.character(args)))!=0){
    with_plots<-F
  }else{
    with_plots<-T
  }
  return(with_plots)
}

extracted_features_argument<-function(args){
  if(length(grep("-e",as.character(args)))!=0){
    extracted_features<-T
  }else{
    extracted_features<-F
  }
  return(extracted_features)
}


extract_features_main<-function(parsed_arguments){
  if(parsed_arguments$extracted_features){
    features<-features_read_in(parsed_arguments$path)
  }else{
    data<-read_in(parsed_arguments$data_path,parsed_arguments$path)
    if(is.null(nrow(data))==F){
      features<-full_features_extraction(data,parsed_arguments)
    }else{
      if(is.null(parsed_arguments$startdate)==T && parsed_arguments$completely==F){
        stop("If the file is to large, hand over a start- and enddate.",.call=F)
      }
      
      features<-parted_feature_extraction_main(parsed_arguments)
    }
  }
  return(features)
}

full_features_extraction<-function(data,parsed_arguments){
  if(parsed_arguments$statistics){
    path_statistics_before<-paste(parsed_arguments$path,"Datenanalyse_vor/",sep="")
    dir.create(path_statistics_before)
    border<-daten_analyse(data,path_statistics_before)
  }
  
  data<-preprocessing(data)
  
  if(parsed_arguments$statistics){
    path_statistics_after<-paste(parsed_arguments$path,"Datenanalyse_nach/",sep="")
    dir.create(path_statistics_after)
    border<-daten_analyse(data,path_statistics_after)
  }
  
  if(parsed_arguments$completely){
    parsed_arguments$startdate<-as_date(min(data$Time))
    parsed_arguments$enddate<-as_date(max(data$Time))
  }else{
    if(parsed_arguments$statistics){
      parsed_arguments$startdate<-border[[1]]
      parsed_arguments$enddate<-border[[2]]
    }else{
      timeline<-timeline_month(data)
      border<-calc_borders(timeline)
      parsed_arguments$startdate<-border[[1]]
      parsed_arguments$enddate<-border[[2]]
    }
  }
  features<-feature_extraction(data,parsed_arguments)
  write.csv(features,paste(parsed_arguments$path,"Features.csv",sep = ""))
  
  return(features)
}

parted_feature_extraction_main<-function(parsed_arguments){
  
  
  finished<-F
  row_multi<-0
  back<-0
  features<-data.frame()
  completely<-parsed_arguments$completely

  while(finished==F){
    data<-parted_read_in(parsed_arguments$path,row_multi,back)
    
    startdatum_man<-parsed_arguments$startdate
    enddatum_man<-parsed_arguments$enddate
    
    if(is.null(nrow(data))==F){
      
      optimized_date<-optimize_date(data,parsed_arguments)
      optimized_arguments<-optimized_date$parsed_arguments
      ignore<-optimized_date$ignore
      finished<-optimized_date$finished
      
      row_multi<-row_multi+1
      
      if(ignore==F){
        parted_feature_extraction_result<-parted_feature_extraction(data,features,finished,optimized_arguments,back,row_multi)
        features<-parted_feature_extraction_result$features
        finished<-parted_feature_extraction_result$finished
        back<-parted_feature_extraction_result$back
      }
      rm(data)
    }else{
      finished<-T
    }
  }
  
  if(parsed_arguments$group==T){
    features<-group_up(features,parsed_arguments$view,parsed_arguments$time_bin,parsed_arguments$cores,load_model=parsed_arguments$load_model,model_path = parsed_arguments$model_path,save_model =parsed_arguments$save_model,path=parsed_arguments$path)
  }
  write.csv(features,paste(parsed_arguments$path,"Features.csv",sep = ""))

  return(features)
}

optimize_date<-function(data,parsed_arguments){
  
  finished<-F
  ignore<-F
  
  if(parsed_arguments$completely!=T){
    
    enddatum_man<-parsed_arguments$enddate
    startdatum_man<-parsed_arguments$startdate
    
    if(startdatum_man>as_date(max(data$Time))){
      ignore<-T
    }else if( enddatum_man<as_date(min(data$Time))){
      finished<-T
      ignore<-T
    }else if(enddatum_man>as_date(max(data$Time))){
      enddatum_man<-as_date(max(data$Time))
    } 
    if(as_date(min(data$Time))>startdatum_man){
      startdatum_man<-as_date(min(data$Time))
    }
  }else{
    enddatum_man<-as_date(max(data$Time))
    startdatum_man<-as_date(min(data$Time))
  }
  
  parsed_arguments$startdate<-startdatum_man
  parsed_arguments$enddate<-enddatum_man
  
  return(list(parsed_arguments=parsed_arguments,ignore=ignore,finished=finished))
}

parted_feature_extraction<-function(data,features,finished,optimized_arguments,back,row_multi){
  time_bin<-optimized_arguments$time_bin
  path<-optimized_arguments$path
  
  tryCatch(expr = {
    check<-read.csv(paste(path,"time_sort.csv",sep=""),nrows = 1,skip=(row_multi*10000000)-back+1,colClasses = c("integer","numeric","POSIXct","numeric","numeric","numeric","integer","integer"),header = F,col.names=c("Event_ID","Host","Time","Logon_ID","User","Source","Source_Port","Logon_Type"))
    if(date(data[nrow(data),3])==date(check[1,3]) && time_bin=="d"){
      data<-data[!(date(data$Time)==date(check[1,3])),]
    }else if(date(data[nrow(data),3])==date(check[1,3]) && hour(data[nrow(data),3])==hour(check[1,3]) && (time_bin=="dh" || time_bin=="h")){
      data<-data[!(date(data$Time)==date(check[1,3]) & hour(data[nrow(data),3])==hour(check[1,3]) ),]
    }
  }, error=function(e){
    finished<-T
  })
  back<-10000000-(nrow(data))
  data<-preprocessing(data)
  features_new<-feature_extraction(data,optimized_arguments,split<-T)
  features<-rbind(features,features_new)
  return(list(features=features,finished=finished,back=back))
}


anomaly_detection<-function(features,parsed_arguments){
  ml<-parsed_arguments$ml
  path<-parsed_arguments$path
  cores<-parsed_arguments$cores
  load_model<-parsed_arguments$load_model
  save_model<-parsed_arguments$save_model
  model_path<-parsed_arguments$model_path
  rank<-parsed_arguments$rank
  absolute_path<-parsed_arguments$absolute_path
  
  if(ml=="IF" || ml=="kNN" || ml=="DAGMM"){
    setup_python(absolute_path)
    tryCatch(expr = {
      if(ml=="IF"){
        isolationforest(absolute_path,path,cores,rank,load_model,save_model,model_path)
      }else if(ml=="kNN"){
        kNN(absolute_path,path,cores,rank,load_model,save_model,model_path)
      }else{
        dagmm(absolute_path,path,rank,load_model,save_model,model_path)
      }
    }, error=function(e){
      stop("An errror appeared into python script.",.call=F)
    })
  }else{
    randomforest(features,parsed_arguments$view,parsed_arguments$time_bin,cores,path,load_model,model_path,save_model)
  }
}

#Aufrufen der Hauptfunktion mit den Argumenten
main(args)

