#!/usr/bin/Rscript --vanilla
#https://www.r-bloggers.com/2019/11/r-scripts-as-command-line-tools/

# Modul:            Praxis-/Bachelorprojekt
# Thema:            Detect Malicious Login Events
# Autorenschaft:    Richard Mey <richard.mey@syss.de>
# Stand:            09.06.2021

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
args <- commandArgs(trailingOnly=TRUE)
file <- commandArgs()

#########
# Setup #
#########

#Legt den Pfad zu den Librarys fest
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

#Dadurch das innerhalb des setups das Script als Linkdatei verfügbar gemacht wird, muss der Vollständige Pfad zu dessem Order ermittelt werden
location_script<-function(file){
  #Extrahieren des Pfades zum Ort wo sich die Link Datei befindet
  file_loc<-sub("[^/]*$","",sub("--file=","",file[grep("--file=.*",file)]))
  if(substring(file_loc,1,1)=="."){
    path_exec<-system("pwd",intern=T)
    link_path<-paste(path_exec,substring(file_loc,2),sep="")
  }else{
    link_path<-substring(file_loc,2)
  }
  #Extrahieren des Realtiven Pfades von der Link Datei zum Orginal
  relativ_path<-Sys.readlink(paste("/",link_path,"FindMaliciousEvents",sep=""))
  #Zusammenfügen beider Informationen
  absolute_path<-paste("/",sub("\\.local/bin/","",link_path),sub("\\.\\./\\.\\./","",sub("FindMaliciousEvents.R$","",relativ_path)),sep="")
  return(absolute_path)
}

#Einlesen der Raw Daten
einlesen<-function(Pfad,Output_Pfad){
  #Da R die Datein in den memory ablegt und es bei zu großen Datein zu einem Crash führt, muss entschieden werden ob die Datei getrennt oder vollständig eingelesen wird
  #Auslesen des freien memorys
  mem<-system('free -m',intern=T)
  mem<-strsplit(mem," ")
  mem<-as.numeric(tail(mem[[2]],n=1))

  #Auslesen der Dateigröße
  size<-as.numeric(file.info(Pfad)$size)

  #Wenn das File keine csv ist oder nicht existiert wird das Programm abgebrochen
    if(file_ext(Pfad)=="csv"){
      #Wenn keine Rechte bestehen die Datei auszulesen, wird das Programm abgebrochen
      if(file.access(Pfad,2)==-1){
        stop("Enter a file for which you got the rights to read.",.call=F)
      }
      
      #Wenn die Rohdatei mind. 40% des Memorys belegn würde, wird die Datei teilweise eingelesen
      if(size>=mem*0.5){
          cat("The specified file is too large, hence the read-in/ preprocessing/ feature extraction will be splited. This process might take more time.",fill=2)
          split<-T
          #Damit die Features vollständig bleiben, wird die Orginal Datei nach der Zeit sortiert
          system(paste("sort -k3 -t, ",Pfad, " >> ", Output_Pfad,"time_sort.csv",sep=""))
          return(split)
        }else{
          #Wenn die Datei kleiner als 40% des freien Memorys ist wird die Datei eingelesen
          tryCatch(expr={
            data<-read.csv(Pfad,colClasses = c("integer","numeric","POSIXct","numeric","numeric","numeric","integer","integer"),header = F)
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
teil_einlesen<-function(Pfad,zeilen_multi,back){
  tryCatch(expr = {
    #Einlesen von x Zeilen und überspringe die vorher bearbeiteten
    data_new<-read.csv(paste(Pfad,"time_sort.csv",sep=""),nrows = 10000000,skip=(zeilen_multi*10000000)-back,colClasses = c("integer","numeric","POSIXct","numeric","numeric","numeric","integer","integer"),header = F)
    colnames(data_new)<-c("Event_ID","Host","Time","Logon_ID","User","Source","Source_Port","Logon_Type")#ActivityID oder LogonGUID
    data_new<-data_new[(data_new$Event_ID==4624),]
    return(data_new)
  }, error = function(e){
    if(zeilen_multi==0){
      stop("Provide a valid, non-empty file and in accordance with the format: Int,Num,Date,Num,Num,Num,Int,Int.",.call=F)
    }else{
      fertig<-T
      return(fertig) 
    }
  }, warning = function(w){
    stop("The file needs the following columns: Event_ID,Host,Time,Logon_ID,User,Source,Source Port,Logon Typ.",.call=F)
  })
}

#Falls die Option -e angeben wurde können die Features, falls schon welche mit dem Programm extrahiert wurden, eingelesen werden 
features_einlesen<-function(Pfad){
  if(file_ext(Pfad)=="csv"){
    if(file.access(Pfad,2)==-1){
      stop("Enter a file for which you got the rights to read.",.call=F)
    }
      tryCatch(expr = {
        features<-read.csv(Pfad,row.names = 1)
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
vorverarbeiten<-function(data){
  data<-data[!(data$User %in% c(0:10000)),]
  data<-data%>% distinct(Event_ID,User,Host,Time,Source,Source_Port,Logon_Type)
  return(data)
}

#Extraktion der Features
feature_extraktion<-function(data,startdatum,enddatum,Sicht,Time_bin,cores,split=F,gruppieren=T,load_model,model_path,save_model,Pfad,Time_bin_size){
  
  #Zuerst werden alle Funktionen zur Features Extraktion definiert
  Identifier<-function(data_user,Sicht,...){
    return(data_user[1,Sicht])
  }
  
  Wochentag<-function(startdatum,i,...){
    return(wday(ymd(as.Date(startdatum) %m+% days(i))))
  }
  
  Stunde<-function(i,...){
    return(as_hms(((i)%%24)*60*60) )
  }
  
  Tag<-function(startdatum,i,...){
    return(as_date((as.Date(startdatum) %m+% hours((i)))))
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
  
  Hosts_per_X<-function(data_user,Sicht,...){
    return((data_user%>% distinct(Host,X=.[[Sicht]]) %>%group_by(X)%>% summarise(n()))$`n()`)
  }
  
  Sources_per_X<-function(data_user,Sicht,...){
    return((data_user%>% distinct(Source,X=.[[Sicht]]) %>%group_by(X)%>% summarise(n()))$`n()`)
  }
  
  Users_per_X<-function(data_user,Sicht,...){
    return((data_user%>% distinct(User,X=.[[Sicht]]) %>%group_by(X)%>% summarise(n()))$`n()`)
  }
  
  
  #Definition, welche Funktionen zur Feature Extraktion dann genutzt werden & welche Namen sie besitzen
  #Dies dient dazu eine gewisse modulartät in den verschiedene Featuren zu schaffen
  feature_funktionen<-c()
  feature_namens<-c()
  
  #Es wird stehts ein Identifiziere mit genutzt
  feature_funktionen<-append(feature_funktionen,Identifier)
  feature_namens<-append(feature_namens,"Identifier")
  i<-0
  #Außerdem wird stehts mindestens ein zeit Format genutzt
  if(Time_bin=="d"){
    feature_funktionen<-append(feature_funktionen,Wochentag)
    feature_namens<-append(feature_namens,"Wochentag")
    zeitfenster<-days
  }else if(Time_bin=="h"){
    feature_funktionen<-append(feature_funktionen,Stunde)
    feature_namens<-append(feature_namens,"Stunde")
    zeitfenster<-hours
  }else{
    feature_funktionen<-append(feature_funktionen,Tag)
    feature_funktionen<-append(feature_funktionen,Stunde)
    feature_namens<-append(feature_namens,c("Tag","Stunde"))
    zeitfenster<-hours
  }
  
  
  #Anschließend werden die normalen Zähl Features eingeschlossen
  feature_funktionen<-append(feature_funktionen,Anzahl_Events)
  feature_namens<-append(feature_namens,"Anzahl_Events")
  
  Types<-list(2,3,9,10,c(11,12))
  start_typ<-length(feature_funktionen)+1
  for(z in 1:5){
    feature_funktionen<-append(feature_funktionen,Anteil_Event)
    feature_namens<-append(feature_namens,paste("Anteil",paste(as.character(unlist(Types[[z]])),collapse="_"),sep = "_"))
  }
  end_typ<-start_typ+5-1
  feature_funktionen<-append(feature_funktionen,Events_per_Second)
  feature_namens<-append(feature_namens,"Events_per_Second")
  
  #Anhand der Sichtweise werden dann die Sichtweise Features hinzugefügt, 2=Sicht Host, 4= Sicht Nutzer, 5= Sicht Quell-IP
  if(Sicht==2){
    feature_funktionen<-append(feature_funktionen,Users_per_X)
    feature_funktionen<-append(feature_funktionen,Sources_per_X)
    feature_namens<-append(feature_namens,c("Users_per_Host","Sources_per_Host"))
  }else if(Sicht==4){
    feature_funktionen<-append(feature_funktionen,Hosts_per_X)
    feature_funktionen<-append(feature_funktionen,Sources_per_X)
    feature_namens<-append(feature_namens,c("Hosts_per_User","Sources_per_User"))
  }else{
    feature_funktionen<-append(feature_funktionen,Users_per_X)
    feature_funktionen<-append(feature_funktionen,Hosts_per_X)
    feature_namens<-append(feature_namens,c("Users_per_Source","Hosts_per_Source"))
  }
  
  #Aufgrund das bei der späteren Ausführung immer die selben Variablen übergeben werden müssen, aber eine modulare abhängigkeit besteht
  #wird eine liste identisch lang zu der Anzahl an Featuren erstellt mit den Informatione zu den Untersuchenden LoginTypen verwendet
  Event_Typ<-rep(list(0),length(feature_funktionen))
  for(z in 1:(end_typ-start_typ+1)-1){
    Event_Typ[[(start_typ+z)]]<-Types[[z+1]]
  }
  
  #Damit der Prozess der Verarbeitung schneller geht wird ein Cluster mit der gegebene Anzahl erstellt
  cl <- makeCluster(cores)
  registerDoParallel(cl)
  
  features<-data.frame()
  #Im Falle aus der Source Sicht müssen die NA Values entfernt werden
  if(Sicht==5){
    data<-data[(is.na(data$Source)!=T),]
  }
  
  cat("Please magnify the window big enough to present the progress bar completly.",fill=2)
  
  #Anlegen eines Fortschrittsbalken, dieser entspricht der Menge an zu bearbeitenden Daten
  zeilen<-nrow(data[(data$Time >=(as.Date(startdatum)) & (data$Time <(as.Date(enddatum)))),])
  fortschritt<-txtProgressBar(min=0, max=zeilen,width = 100,style = 3, char="=", file=stderr(),title="Feature extraction:")
  bearbeitet<-0
  
  #Durchäuft anschlißend abhängig von der Zeiteinheit jeden Tag/Stunde bis zur Abbruchbedingung
  repeat{
    #Extrahiert alle Daten in dem Zeitraum
    window<-data[(data$Time >=(as_datetime(startdatum) %m+% zeitfenster(i)) & (data$Time <(as_datetime(startdatum)%m+% zeitfenster(i+1+Time_bin_size)))),]
    #Falls es leer ist ->überspringe
    if(nrow(window)>0){
      #Extrahiert je nach Scihtweise und duplikatslos die Nutzer/Hosts/Quell-IPs
      iter<- distinct(window,window[[Sicht]])
      #Durchläuft anschließend die Liste in parallelister Form für jeden Nutzer/Host/Quell-IP
      ergebnisse<-foreach(j=1:length(iter[,1]),.packages = c("lubridate","dplyr","hms","R.utils"),.combine = rbind) %dopar%{
        #Extrahiert die Sichtdaten
        data_user<-window[(window[,Sicht]==iter[j,1]),]
        ergebnis<-data.frame()
        #Wendet die Funktionen für die Featureextraktion an
        for(k in 1:length(feature_funktionen)){
          ergebnis[1,k]<-doCall(feature_funktionen[[k]],args=list(data_user=data_user,Sicht=Sicht,startdatum=startdatum,i=i,Event_Typ=Event_Typ[[k]]),.ignoreUnusedArgs=T)
        }
        return(ergebnis)
      }
      #Fügt das Ergebnisses jedes Durchlaufs hinzu
      features<-rbind(features,ergebnisse)
      
      #Erhöht die bereits durch itertriten Datensätze & gibt es aus
      bearbeitet<-bearbeitet+nrow(window)
      setTxtProgressBar(fortschritt,bearbeitet,title="Feature extraction:") 
      flush.console()
    }
    
    #Abbruchbedingung
    if((as_datetime(startdatum)%m+% zeitfenster(i+1+Time_bin_size))>=as_datetime(enddatum)){
      break
    }
    i<-i+1+Time_bin_size
  }
  #Stoppen des Clusters
  stopCluster(cl)
  close(fortschritt)
  
  #Gibt den Features die Namen
  colnames(features)<-feature_namens
  
  #Wenn die Daten nicht gesplittet vorliegen, Cluster diese
  if(split!=T && gruppieren==T){
    features<-gruppierung(features,Sicht,Time_bin,cores,load_model=load_model,model_path=model_path,save_model=save_model,Pfad=Pfad)
  }

  return(features)
}

#Berechnen der Mittelwertdaten
calc_means<-function(features,Sicht,cores){
  
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
clustern<-function(iter_means,features,k,label,load_model,model_path,save_model,Pfad){
  
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
    saveRDS(km.res,paste(Pfad,"model/cluster.rds",sep = ""))
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

min_max_calc<-function(features,Time_bin){
  if(Time_bin=="dh"){
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
gruppierung<-function(features,Sicht,Time_bin,cores,label=F,load_model,model_path,save_model,Pfad){
  #Berechnung Mittelwerte
  iter_means<-calc_means(features,Sicht,cores)
  #Cluster zuweisung
  features<-clustern(iter_means,features,13,label,load_model,model_path,save_model,Pfad)
  
  if(save_model && label==F){
    min_max<-min_max_calc(features,Time_bin)
    saveRDS(min_max,paste(Pfad,"model/min_max.rds",sep=""))
  }
  
  #Führe eine 0-1 Normalisierung durch, falls es nicht als Label verwendet werden soll -> sorgt für Beschleunigung der Lerner
  if(label==F){
    if(load_model){
      min_max<-readRDS(paste(model_path,"min_max.rds",sep=""))
      min_max_new<-min_max_calc(features,Time_bin)
      min_max<-as.numeric(unlist(min_max_calc_2(min_max,min_max_new)))
      if(Time_bin=="dh"){
        features[,3:(ncol(features)-1)]<-normalize_min_max(features[,3:(ncol(features)-1)],min_max)
      }else{
        features[,2:(ncol(features)-1)]<-normalize_min_max(features[,2:(ncol(features)-1)],min_max)
      }
    }else{
      if(Time_bin=="dh"){
        features[,3:(ncol(features)-1)]<-normalize(features[,3:(ncol(features)-1)],method="range",range = c(0,1))
      }else{
        features[,2:(ncol(features)-1)]<-normalize(features[,2:(ncol(features)-1)],method="range",range = c(0,1))
      }
    }
  }
  
  return(features)
}

#Prüft ob Python 3 installiert ist, falls ja aktiviert es ein demenstprechendes vorher aktiviertes virtuell envirmoment
setup_python<-function(Pfad){
  tryCatch(expr={
    use_python(as.character(system("which python3",intern = T)))
  },error=function(e){
    stop("Python 3 is not installed.",.call=F)
  })
  use_virtualenv(paste(Pfad,"maliciousevents",sep=""))
}

#Führt das Python Funktion mit dem Isolationsbaum aus
isolationforest<-function(Input_Pfad,Output_Pfad,cores,rank,load_model,save_model,model_path){
  source_python(paste(Input_Pfad,"ml/IsolationForest_Anwendung.py",sep=""))
  isolationforest_exec(Input_Pfad,Output_Pfad,as.integer(cores),rank,load_model,save_model,model_path)
}

#Führt die Python Funktion mit dem kNN aus
kNN<-function(Input_Pfad,Output_Pfad,cores,rank,load_model,save_model,model_path){
  source_python(paste(Input_Pfad,"ml/kNN_Anwendung.py",sep=""))
  knn_exec(Input_Pfad,Output_Pfad,as.integer(cores),rank,load_model,save_model,model_path)
}

#Führt die Python Funktion mit dem DAGMM aus
dagmm<-function(Input_Pfad,Output_Pfad,cores,rank,load_model,save_model,model_path){
  source_python(paste(Input_Pfad,"ml/DAGMM_Anwendung.py",sep=""))
  dagmm_exec(Input_Pfad,Output_Pfad,as.integer(cores),rank,load_model,save_model,model_path)
}

#Nutzt einen Random Forest um Nutzer/hosts/Quell-IPs die viele Gruppen besuchen als ungewöhnlich einzustuffen
randomforest<-function(features,Sicht,Time_bin,cores,Pfad,load_model,model_path,save_model){
  #Clustert die Daten und gibt die Mittelwertdaten+ die Clusternummer als Label zurück
  means_label<-gruppierung(features,Sicht,Time_bin,cores,label = T,load_model,model_path,save_model,Pfad)
  
  if(load_model){
    model<-readRDS(paste(model_path,"model.rds",sep=""))
    tryCatch(
      expr = {
        model_type=attr(model$forest,"class")
        if(model_type!="ranger.forest"){
          stop("Use the correct model on load with the correct machine learning option.",.call=F)
        }
      }, error = function(e){
        stop("Use the correct model on load with the correct machine learning option.",.call=F)
      }
    )
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
    saveRDS(model,paste(Pfad,"model/","model.rds",sep=""))
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
  write.csv(result,paste(Pfad,"Ergebnisse.csv",sep=""))
}

#Zur Visualierung werden Radarplots der erkannten Anomalien erstellt+ausgeben
visualisierung_ergebnisse<-function(features,Output_Pfad,NOT_RF,rank){
  
  ergebnisse<-read.csv(paste(Output_Pfad,"Ergebnisse.csv",sep=""))
  
  if("Stunde" %in% colnames(features)){
    features["Stunde"]<-as.numeric(seconds(as_hms(sapply(features["Stunde"],as.character))))
    ergebnisse["Stunde"]<-as.numeric(seconds(as_hms(sapply(ergebnisse["Stunde"],as.character))))
  }
  
  identifier<-data.frame(Identifier=sub("^X","",sub("\\.[0-9]*$","",ergebnisse[,1])))
  iter<-distinct(identifier,Identifier=Identifier)
  if(NOT_RF==F || rank ==T){
    iter<-iter %>% slice(1:50)
  }
  
  Output_Pfad<-paste(Output_Pfad,"Radarplots/",sep="")
  dir.create(Output_Pfad)
  
  palette <- colorRampPalette(colors=c("#000000", "#FFFFF0"))
  palette_outsider<-colorRampPalette(c("red","purple"))
  par(mar = c(1, 1, 2, 1))
  par(oma=c(0,0,0,0))
  
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
      insider<-subset(insider,!(insider %in% outsider))
      
      cols[1:(length(cols)-length(outsider))]<-palette((length(cols)-length(outsider)))
      if(NOT_RF==T){
        cols[(length(cols)-length(outsider)+1):length(cols)]<-palette_outsider(length(outsider)) 
        plot_data<-rbind(select(features[insider,],!one_of(c("User","Identifier","Tag"))),select(features[outsider,],!one_of(c("User","Identifier","Tag"))))
      }else{
        plot_data<-insider[-c(1)]
      }
      

      cols_in <- alpha(cols,0.2)
      
      jpeg(paste(Output_Pfad,iter[i,1],".jpg",sep=""), width = 1900, height = 1900,quality=100,pointsize = 40,res=120)
      radarchart(plot_data,maxmin = F,axistype = 1,pcol=cols,pfcol=cols_in, plwd=1 , plty=2, cglty=1,cglwd=0.8, cglcol="#466D3A",vlcex=0.8,axislabcol="#00008B" )
      dev.off()  
  }
}

###Datenanlyse Funktionen
daten_analyse<-function(data,Pfad){
  allgemeine_infos(data,Pfad)
  logintypen(data,Pfad)
  timeline<-timeline_month(data,Pfad)
  borders<-calc_borders(timeline)
  timeline_day(data,Pfad,borders[[1]],borders[[2]])
  return(borders)
}

logintypen<-function(data,Pfad){
  logontype<-data.frame()
  for(i in 1:14-1){
    logontype_x<-data[(data$Logon_Type==i),]
    logontype[i+1,1]<-i
    logontype[i+1,2]<-length(logontype_x[,1])
  }
  logontype_plot<-ggplot(data=logontype,aes(x=logontype[,1],y=logontype[,2])) +
    geom_bar(stat="identity")+
    xlab("Logon Type") + ylab("Anzahl")
  
  ggsave(paste(Pfad,"Login_Typen.png",sep=""),logontype_plot,width = 10,dpi=300,limitsize = F)
}

allgemeine_infos<-function(data,Pfad){
  infos<-c()
  infos[1]<-paste("Existing Well known Source Ports:",paste(as.character(c(data[(data$Source_Port %in% c(1:1023) & is.na(data$Source_Port)!=T),"Source_Port"])),collapse=", "))
  infos[2]<-paste("Number of Hosts:",nrow(group_by(data,data$Host) %>% summarise(n())))
  infos[3]<-paste("Number of Users:",nrow(group_by(data,data$User) %>% summarise(n())))
  infos[4]<-paste("Number of Source-IPs:",nrow(group_by(data,data$Source) %>% summarise(n())))
  infos[5]<-paste("Smallest date of the data:",min(data$Time))
  infos[6]<-paste("Newest date:",max(data$Time))
  write.table(infos,file=paste(Pfad,"Allgemeine_Infos.txt",sep=""),row.names = F,col.names = F)
}

timeline_month<-function(data,Pfad=0){
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
  
  if(Pfad!=0){
    timeplot<-ggplot(timeline,aes(x=Time,y=Anzahl))+
      geom_area(fill="#69b3a2",alpha=0.5)+
      geom_line()
    
    ggsave(paste(Pfad,"Volle_Zeitreihe_in_Monaten.png",sep=""),timeplot,width = 50,dpi=300,limitsize = F)
  }
  
  return(timeline)
}

calc_borders<-function(timeline){
  timeline[,3]<-scale(timeline[,2])
  border<-as.numeric(quantile(timeline[,3],(0.90+nrow(timeline)*0.00019)))
  left<-timeline[timeline[,3]>border,]
  return(list(left[1,1],as.Date(left[nrow(left),1]) %m+%months(1)))
}

timeline_day<-function(data,Pfad,startdatum,enddatum){
  i<-0
  timeline<-data.frame()
  repeat{
    timeline[i+1,1]<-(as.Date(startdatum)%m+% days(i))
    timeline[i+1,2]<-nrow(data[(data$Time >=(as.Date(startdatum)%m+% days(i)) & (data$Time <(as.Date(startdatum)%m+% days(i+1)))),])
    
    if((as.Date(startdatum)%m+% days(i))==as.Date(enddatum)){
      break
    }
    i<-i+1
  }
  
  colnames(timeline)<-c("Time","Anzahl")
  
  timeplot<-ggplot(timeline,aes(x=Time,y=Anzahl))+
    geom_area(fill="#69b3a2",alpha=0.5)+
    geom_line()
  
  ggsave(paste(Pfad,"Quantil_Zeitreihe_Tage.png",sep=""),timeplot,width = 50,dpi=300,limitsize = F)
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
        "-da       Gives an additional data analysis output",
        "-p        Specification of the perspective with the following argument, default is User",
        "          u User   From a users point of view",
        "          h Host   From a hosts point of view",
        "          s Source From a source point of view",
        "-t        Specification of the time slot with the following argument, default is day",
        "          h Hour",
        "          d Day",
        "          dh Day&Hour",
        "             default is one hour for h&dh, write a number of hours behind it to change it",
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
        "-lm       The next argument should be the path to the directory with the trained model information",fill=2)
}

#################
# Main Funktion #
#################

#Hauptfunktion steuert, welche Funktionen aufgerufen werden aufgrund der übergebenen Argumente
main<-function(args,file){
  if(length(args)==0){
    stop("Es muss mindestens ein Datensatz und ein Ausagebort angegeben werden",.call=F)
  }else if(args[1]=="--help"){
    help_output()
  }else if(file.exists(args[1])==F){
    stop("Es muss eine existierende Datei angegeben werden",.call=F)
  }else if(dir.exists(args[2])==F){
    stop("Es muss ein existierendes Verzeichnis angeben werden",.call=F)
  }else{
    data_analysis<-F
    if(file.access(as.character(args[2]),c(4,2))==-1){
      stop("Gebe einen Speicherort an, indem du ausreichend Rechte besitzt (w,r).",.call=F)
    }
   Pfad<-tryCatch(expr = {
      Pfad<-paste(as.character(args[2]),"/FindMaliciousEvents_1/",sep="")
      dir.create(Pfad)
    }, warning=function(w){
      dir<-list.dirs(as.character(args[2]),recursive = F,full.names = F)
      dir_ME<-grep("FindMaliciousEvents_[0-9]+",dir)
      Pfad<-paste(as.character(args[2]),"/FindMaliciousEvents_",(max(as.numeric(sub("[^0-9]+","",dir[dir_ME])))+1),"/",sep="")
      dir.create(Pfad)
      return(Pfad)
    }, finally = {
    })

    if(length(grep("-da",as.character(args)))!=0 && grep("-da",as.character(args))>2){
      data_analysis<-T
    }
    
    Sicht<-4
    Time_bin<-"d"
    Time_bin_size<-0
    write_features<-F
    
    if(length(grep("-p",as.character(args)))!=0){
      if(length(args[grep("-p",as.character(args))+1])!=1){
        stop("Wähle einer der Optionen für die Sichtweise (u,h,s)",.call=F)
      }else{
            if(as.character(args[grep("-p",as.character(args))+1])=="u" ||as.character(args[grep("-p",as.character(args))+1])=="h" ||as.character(args[grep("-p",as.character(args))+1])=="s" ){
              if(as.character(args[grep("-p",as.character(args))+1])=="u"){
                Sicht<-4
              }else if(as.character(args[grep("-p",as.character(args))+1])=="h"){
                Sicht<-2
              }else{
                Sicht<-5
              }
            }else{
              stop("Wähle einer der gültigten Optionen für die Sichtweise (u,h,s)",.call=F)
            }
          }
      }
    
    ml<-"IF"
    gruppieren<-T
    
    if(length(grep("-m",as.character(args)))!=0){
      if(length(args[grep("-m",as.character(args))+1])!=1){
        stop("Wähle einer der Optionen für das machine learning (IF,kNN,RF)",.call=F)
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
            gruppieren<-F
          }
        }else{
          stop("Wähle einer der gültigten Optionen für das machine learning (IF,kNN,RF)",.call=F)
        }
      }
    }
    
    if(length(grep("-t",as.character(args)))!=0){
      if(length(args[grep("-t",as.character(args))+1])!=1){
        stop("Wähle einer der Optionen für die Zeitblöcke (d,h,dh)",.call=F)
      }else{
        if(as.character(args[grep("-t",as.character(args))+1])=="h" ||as.character(args[grep("-t",as.character(args))+1])=="d" ||as.character(args[grep("-t",as.character(args))+1])=="dh"){
          if(as.character(args[grep("-t",as.character(args))+1])=="d"){
            Time_bin<-"d"
          }else{
            if(as.character(args[grep("-t",as.character(args))+1])=="h"){
              Time_bin<-"h" 
            }else{
              Time_bin<-"dh"
            }
            
            if(length(args[grep("-t",as.character(args))+2])!=1){
              if(length(grep("^[0-9]*$",as.character(args[grep("-t",as.character(args))+2])))!=0){
                Time_bin_size<-as.numeric(args[grep("-t",as.character(args))+2])-1
                if(Time_bin_size<0 || Time_bin_size >71){
                  stop("Please insert a number of hours bigger then 0 and smaller then 73.",.call=F)
                }
              }else{
                stop("Please insert a number behind the hour/day-hour time bin format.",.call=F)
              }
            }else{
            }
          }
        }else{
          stop("Wähle einer der gültigten Optionen für die Zeitblöcke (d,h,dh)",.call=F)
        }
      }
    }
    
    if(length(grep("-r",as.character(args)))!=0){
      rank<-T
    }else{
      rank<-F
    }
    
    load_packages()
    
    if(length(grep("-p",as.character(args)))!=0){
      if(length(args[grep("-p",as.character(args))+1])!=1){
        stop("Gebe eine Anzahl an verwendeten Prozessoren an.",.call=F)
      }else{
        tryCatch(expr = {
          cores<-as.numeric(args[grep("-p",as.character(args))+1])
          if(cores>detectCores()){
            stop("Deine angebene Kernanzahl ist größer als die verfügbare.",.call=F)
          }
        },warning=function(w){
          stop("Gebe eine Zahl ein, entsprechend deiner Cores an.",.call=F)
        })
      }
    }else{
      cores<-detectCores()-1
    }
    
    if(length(grep("-lm",as.character(args)))!=0){
      if(length(args[grep("-lm",as.character(args))+1])!=1){
        stop("You need to hand over a path to the directory with the model information.",.call=F)
      }else{
        model_path<-as.character(args[grep("-lm",as.character(args))+1])
        if(dir.exists(model_path)==F){
          stop("You need to hand over an existing model directory.",.call=F)
        }
        if(file.exists(paste(model_path,"cluster.rds",sep=""))==F || file.exists(paste(model_path,"min_max.rds",sep=""))==F || (file.exists(paste(model_path,"model.joblib",sep=""))==F && file.exists(paste(model_path,"model.rds",sep=""))==F) ){
          stop("Hand over a directory that contains the following content: min_max.rds, cluster.rds, model.(rds/joblib)",.call=F)
        }
        
        if((file.exists(paste(model_path,"model.rds",sep=""))==F && ml=="RF") || (file.exists(paste(model_path,"model.rds",sep=""))==T && (ml=="IF" || ml=="kNN"))){
          stop("Use the correct model on load with the correct machine learning option.",.call=F)
        }
        load_model<-T
      }
    }else{
      model_path<-""
      load_model<-F
    }
    
    if(length(grep("-s",as.character(args)))!=0){
      save_model<-T
      dir.create(paste(Pfad,"model/",sep=""))
    }else{
      save_model<-F
    }
    

    #unix::rlimit_as(1e12, 1e12)
    
    if(length(grep("-e",as.character(args)))==0){
            data<-einlesen(as.character(args[1]),Pfad)
      if(is.null(nrow(data))==F){
        if(data_analysis==T){
          Pfad_da_vor<-paste(Pfad,"Datenanalyse_vor/",sep="")
          dir.create(Pfad_da_vor)
          border<-daten_analyse(data,Pfad_da_vor)
        }
        data<-vorverarbeiten(data)
        if(data_analysis==T){
          Pfad_da_nach<-paste(Pfad,"Datenanalyse_nach/",sep="")
          dir.create(Pfad_da_nach)
          border<-daten_analyse(data,Pfad_da_nach)
        }
        
        if(length(grep("-d",as.character(args)))!=0){
          if(length(args[grep("-d",as.character(args))+1])!=1){
            stop("Wähle einer der Optionen für die Start- und Enddaten (m,v)",.call=F)
          }else{
            if(as.character(args[grep("-d",as.character(args))+1])=="m" ||as.character(args[grep("-d",as.character(args))+1])=="v"){
              if(as.character(args[grep("-d",as.character(args))+1])=="m"){
                if(length(args[grep("-d",as.character(args))+2])!=1 && length(args[grep("-d",as.character(args))+3])!=1){
                  stop("Gebe ein Start- & Enddatum an.",.call=F)
                }else{
                  tryCatch(expr = {
                    startdatum<-as_date(args[grep("-d",as.character(args))+2])
                    enddatum<-as_date(args[grep("-d",as.character(args))+3])
                  }, warning = function(w){
                    stop("Gebe ein gültiges Start- bzw. Enddatum an.",.call=F)
                  })
                  if(startdatum>enddatum){
                    stop("Dein Startdatum ist jünger als dein Enddatum, bitte Tausche deine Angaben.",.call=F)
                  }
                }
              }else{
                startdatum<-as_date(min(data$Time))
                enddatum<-as_date(max(data$Time))
              }
            }else{
              stop("Wähle einer der gültigten Optionen für die  Start- und Enddaten (m,v)",.call=F)
            }
          }
        }else{
          if(data_analysis==T){
            startdatum<-border[[1]]
            enddatum<-border[[2]]
          }else{
            timeline<-timeline_month(data)
            border<-calc_borders(timeline)
            startdatum<-border[[1]]
            enddatum<-border[[2]]
          }
        }
        
        features<-feature_extraktion(data,startdatum,enddatum,Sicht,Time_bin,cores,gruppieren = gruppieren,load_model = load_model,Pfad = Pfad,save_model = save_model,model_path = model_path,Time_bin_size=Time_bin_size)
        write.csv(features,paste(Pfad,"Features.csv",sep = ""))
      }else{
        fertig<-F
        zeilen_multi<-0
        back<-0
        features<-data.frame()
        vollstaendig<-F
        
        if(length(grep("-d",as.character(args)))!=0){
          if(length(args[grep("-d",as.character(args))+1])!=1){
            stop("Wähle einer der Optionen für die Start- und Enddaten (m,v)",.call=F)
          }else{
            if(as.character(args[grep("-d",as.character(args))+1])=="m" ||as.character(args[grep("-d",as.character(args))+1])=="v"){
              if(as.character(args[grep("-d",as.character(args))+1])=="m"){
                if(length(args[grep("-d",as.character(args))+2])!=1 && length(args[grep("-d",as.character(args))+3])!=1){
                  stop("Gebe ein Start- & Enddatum an.",.call=F)
                }else{
                  tryCatch(expr = {
                    startdatum<-as_date(args[grep("-d",as.character(args))+2])
                    enddatum<-as_date(args[grep("-d",as.character(args))+3])
                  }, warning = function(w){
                    stop("Gebe ein gültiges Start- bzw. Enddatum an.",.call=F)
                  })
                  if(startdatum>enddatum){
                    stop("Dein Startdatum ist jünger als dein Enddatum, bitte Tausche deine Angaben.",.call=F)
                  }
                }
              }else{
                vollstaendig<-T
              }
            }else{
              stop("Wähle einer der gültigten Optionen für die  Start- und Enddaten (m,v)",.call=F)
            }
          }
        }else{
          stop("Falls die Datei zu Groß ist musst du ein Start- bzw. Enddatum festlegen.",.call=F)
        }
        while(fertig==F){
          data<-teil_einlesen(Pfad,zeilen_multi,back)
          
          startdatum_man<-startdatum
          enddatum_man<-enddatum
          
          if(is.null(nrow(data))==F){
            
            ignore<-F
            
            if(vollstaendig!=T){
              if(startdatum_man>as_date(max(data$Time))){
                ignore<-T
              }else if( enddatum_man<as_date(min(data$Time))){
                fertig<-T
                ignore<-T
              }else if(enddatum_man>as_date(max(data$Time))){
                enddatum_man<-as_date(max(data$Time))
              } 
            }else{
              enddatum_man<-as_date(max(data$Time))
            }
            
            if(as_date(min(data$Time))>startdatum_man){
              startdatum_man<-as_date(min(data$Time))
            }
            
            zeilen_multi<-zeilen_multi+1
            
            if(ignore==F){
              tryCatch(expr = {
                check<-read.csv(paste(Pfad,"time_sort.csv",sep=""),nrows = 1,skip=(zeilen_multi*10000000)-back+1,colClasses = c("integer","numeric","POSIXct","numeric","numeric","numeric","integer","integer"),header = F,col.names=c("Event_ID","Host","Time","Logon_ID","User","Source","Source_Port","Logon_Type"))
                if(date(data[nrow(data),3])==date(check[1,3]) && Time_bin=="d"){
                  data<-data[!(date(data$Time)==date(check[1,3])),]
                }else if(date(data[nrow(data),3])==date(check[1,3]) && hour(data[nrow(data),3])==hour(check[1,3]) && (Time_bin=="dh" || Time_bin=="h")){
                  data<-data[!(date(data$Time)==date(check[1,3]) & hour(data[nrow(data),3])==hour(check[1,3]) ),]
                }
              }, error=function(e){
                fertig<-T
              })
              back<-10000000-(nrow(data))
              data<-vorverarbeiten(data)
              features_new<-feature_extraktion(data,startdatum_man,enddatum_man,Sicht,Time_bin,cores,split=T,load_model = load_model,Pfad = Pfad, save_model = save_model,model_path = model_path,Time_bin_size=Time_bin_size)
              features<-rbind(features,features_new)
            }
            rm(data)
          }else{
            fertig<-T
          }
        }
        
        if(gruppieren==T){
          features<-gruppierung(features,Sicht,Time_bin,cores,load_model=load_model,model_path = model_path,save_model =save_model,Pfad=Pfad)
        }
        write.csv(features,paste(Pfad,"Features.csv",sep = ""))
      }
  
      
        
    }else{
      features<-features_einlesen(as.character(args[grep("-e",as.character(args))+1]))
    }
    
    absoluter_pfad<-location_script(file)
    if(ml=="IF" || ml=="kNN" || ml=="DAGMM"){
      setup_python(absoluter_pfad)
      if(ml=="IF"){
        isolationforest(absoluter_pfad,Pfad,cores,rank,load_model,save_model,model_path)
      }else if(ml=="kNN"){
        kNN(absoluter_pfad,Pfad,cores,rank,load_model,save_model,model_path)
      }else{
        dagmm(absoluter_pfad,Pfad,cores,rank,load_model,save_model,model_path)
      }
    }else{
      randomforest(features,Sicht,Time_bin,cores,Pfad,load_model,model_path,save_model)
    }
    visualisierung_ergebnisse(features,Pfad,gruppieren,rank)
    system("clear")
    }

}

#Aufrufen der Hauptfunktion mit den Argumenten
main(args,file)

