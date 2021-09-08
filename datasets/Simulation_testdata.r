library(lubridate)
options(lubridate.week.start=1)

days<-500
users<-100
workstations<-110
sources<-70


testset<-data.frame()
users_names<-sample(10001:10000000,size=users)
workstations_names<-sample(10001:10000000,size=workstations)
sources_names<-sample(10001:10000000,size=sources)

connection_type<-function(first_time,users_normal,users_names_normal,testset,mid_day){
  type<-c()
  if(first_time){
    type<-sample(c(2,10),users_normal,replace = T,prob = c(0.95,0.05))
  }else{
    for(i in 1:users_normal){
      types<-testset[users_names_normal[i]==testset[,5] & (testset[,8]==2 | testset[,8]==10),8]
      count<-table(types)
      prefer<-as.numeric(names(which.max(count)))
      if(mid_day){
        if(prefer==10){
          type[i]<-10
        }else{
          x<-c(2,7,11)
          prob<-c(0.55,0.25,0.2)
          type[i]<-sample(x,1,replace = T,prob = prob)
        }
      }else{
        if(prefer==10){
          prob<-c(0.05,0.95)
        }else{
          prob<-c(0.95,0.05)
        }
        type[i]<-sample(c(2,10),1,replace = T,prob = prob)
      } 
      }
  }
  return(type)
}

workstation_choose<-function(first_time,users_normal,user_names_normal,workstations_names,testset){
  workstation<-c()
  if(first_time){
    workstation<-sample(workstations_names,users_normal)
  }else{
    for(i in 1:users_normal){
      workstations<-testset[users_names_normal[i]==testset[,5] & (testset[,8] %in% c(2,7,10,11)),2]
      count<-as.data.frame(table(workstations))
      count<-count[order(count$Freq,decreasing = T),]
      count[,3]<-match(count[,1],workstations_names)
      prob<-c(sample(0.05/length(workstations_names),length(workstations_names),replace = T))
      prob_per_occur<-0.95/sum(count$Freq)
      for(j in 1:nrow(count)){
        prob[count[j,3]]<-prob_per_occur*count[j,2]
      }
      workstation[i]<-sample(workstations_names,1,prob=prob)
    }
  }
  return(workstation)
}

source_allocation<-function(type,users,sources_names,sources){
  source<-c()
  for(i in 1:users){
    if(type[i]==2 || type[i]==7 || type[i]==11){
      source[i]<-sources_names[1]
    }else{
      source[i]<-sample(sources_names[2:sources],1)
    }
  }
  return(source)
}

source_port_allocation<-function(source,users,sources_names){
  source_port<-c()
  for(i in 1:users){
    if(source[i]==sources_names[1]){
      source_port[i]<-0
    }else{
      source_port[i]<-sample(c(1024:65534),1)
    }
  }
  return(source_port)
}

build_group<-function(users){
  group<-sample(c(1,2,3,4),users,replace=T,prob = c(0.225,0.6,0.15,0.025))
  return(group)
}

build_sample<-function(users_normal,users_names_normal,workstations,workstations_names,sources,sources_names,first_time,testset,time,date,mid_day){
  type<-connection_type(first_time,users_normal,users_names_normal,testset,mid_day)
  workstation<-workstation_choose(first_time,users_normal,user_names_normal,workstations_names,testset)
  source<-source_allocation(type,users_normal,sources_names,sources)
  source_port<-source_port_allocation(source,users_normal,sources_names)
  datetime<-sapply(time,function(x){return(date+seconds(x))})
  datetime<-as_datetime(datetime)
  new_testset<-data.frame(Event_Typ=4624,Host=workstation,Date=datetime,ID=1,User=users_names_normal,Source=source,Source_Port=source_port,Logon_Type=type)
  testset<-rbind(testset,new_testset)
  return(testset)
}

build_sample_2<-function(users,users_names,workstations,workstations_names,sources,sources_names,first_time,testset,workstart,workend,lunchstart,lunchend,date,group){
  event_anzahl<-c()
  time_type<-c()
  for(i in 1:length(group)){
    if(group[i]==1){
      mean<-0
      sd<-0
      allday<-F
    }else if(group[i]==2){
      mean<-4
      sd<-2
      allday<-F
    }else if(group[i]==3){
      mean<-30
      sd<-10
      allday<-F
    }else{
      mean<-100
      sd<-20
      allday<-T
    }
    event_anzahl[i]<-round(rnorm(1,mean,sd),digits = 0)
    time_type[i]<-allday
  }
  
  for(i in 1:users){
    workstation<-c()
    source<-c()
    source_port<-c()
    if(event_anzahl[i]>0){
      workstation<-append(workstation,sample(workstations_names,replace=T,event_anzahl[i]))
      source<-append(source,sample(sources_names[2:sources],replace=T,event_anzahl[i]))
      source_port<-append(source_port,sample(c(1024:65534),replace=T,event_anzahl[i]))
      
      if(time_type[i]){
        time<-sample(c(1:86400),event_anzahl[i])
      }else{
        time<-sample(c(workstart[i]:lunchstart[i],lunchend[i]:workend[i]),event_anzahl[i])
      }
      
      datetime<-sapply(time,function(x){return(date+seconds(x))})
      datetime<-as_datetime(datetime)
      new_testset<-data.frame(Event_Typ=4624,Host=workstation,Date=datetime,ID=1,User=users_names[i],Source=source,Source_Port=source_port,Logon_Type=3)
      testset<-rbind(testset,new_testset) 
    }
  }
  return(testset)
}

for (i in 1:days) {
  
  date<-as_datetime("2021-05-31")+days(i)
  
  mid_day<-F
  
  if(i==1){
    first_time<-T
    group<-build_group(users)
    users_not_normal<-which(group %in% 4)
    users_normal<-users-length(users_not_normal)
    users_names_normal<-users_names[-c(users_not_normal)]
  }else{
    first_time<-F
  }
  
  if(wday(date)!=6 && wday(date)!=7){
    workstart<-rnorm(users,mean=28800,sd=600)
    workstart_normal<-workstart[-c(users_not_normal)]
    testset<-build_sample(users_normal,users_names_normal,workstations,workstations_names,sources,sources_names,first_time,testset,workstart_normal,date,mid_day)
    first_time<-F
    mid_day<-T
    
    lunchstart<-rnorm(users,mean=45000,sd=1800)
    lunchstart_normal<-lunchstart[-c(users_not_normal)]
    lunchtime<-rnorm(users,mean = 1800,sd=300)
    lunchend<-lunchstart+lunchtime
    lunchend_normal<-lunchend[-c(users_not_normal)]
    testset<-build_sample(users_normal,users_names_normal,workstations,workstations_names,sources,sources_names,first_time,testset,lunchend_normal,date,mid_day)
    
    worktime<-rnorm(users,mean=28800,sd=300)
    workend<-workstart+worktime
    workend_normal<-workend[-c(users_not_normal)]
    testset<-build_sample_2(users,users_names,workstations,workstations_names,sources,sources_names,first_time,testset,workstart,workend,lunchstart,lunchend,date,group)
    
    for(j in 1:users_normal){
      breaks<-round(rnorm(1,mean=5,sd=2),digits = 0)
      if(breaks>0){
        break_time<-sample(c(workstart_normal[j]:lunchstart_normal[j],lunchend_normal[j]:workend_normal[j]),breaks)
        testset<-build_sample(breaks,rep(users_names_normal[j],breaks),workstations,workstations_names,sources,sources_names,first_time,testset,break_time,date,mid_day)
      }
    }
  }
  
}

write.table(testset,"/home/rmey/Dokumente/my_projekt/Testset/Version_3.csv",row.names = F,col.names = F,sep=",")

### Adding Testcases
library(lubridate)
options(lubridate.week.start=1) #Wochentag beginnt Montag
Sys.setenv(TZ='UTC')
## Viele Hosts bei einem Nutzer bei dem es untypisch ist, Version 2 nutzen
user_to_manipulate=1196840
testset<-rbind(testset,data.frame(Event_Typ=4624,Host=sample(workstations_names,1),Date="2021-06-15 08:00:00 UTC",ID=1,User=user_to_manipulate,Source=sources_names[1],Source_Port=0,Logon_Type=2))

#Hosts+1Tag
for(i in 1:50){
  datetime<-as_datetime(as_datetime("2021-06-15 00:00:00 UTC")+minutes(i*15))
  testset<-rbind(testset,data.frame(Event_Typ=4624,Host=sample(workstations_names,1),Date=datetime,ID=1,User=user_to_manipulate,Source=sources_names[1],Source_Port=0,Logon_Type=2))
}

#Host+ mehrere Tage hintereinander
for(j in 1:10){
  date<-as_datetime("2021-06-15 00:00:00 UTC")+days(j)
  if(wday(date)!=6 && wday(date)!=7){
    freq<-sample(30:70,1)
    for(i in 1:freq){
      datetime<-as_datetime(date+minutes(i*15))
      testset<-rbind(testset,data.frame(Event_Typ=4624,Host=sample(workstations_names,1),Date=datetime,ID=1,User=user_to_manipulate,Source=sources_names[1],Source_Port=0,Logon_Type=2))
    }
  }
}

#Host+ mehrere Tage, aber nicht hintereinander
for(j in 1:10){
  date<-as_datetime("2021-06-15 00:00:00 UTC")+days(j)
  active<-sample(c(1,0),1,prob=c(0.65,0.35))
  if(wday(date)!=6 && wday(date)!=7 && active){
    freq<-sample(30:70,1)
    for(i in 1:freq){
      datetime<-as_datetime(date+minutes(i*15))
      testset<-rbind(testset,data.frame(Event_Typ=4624,Host=sample(workstations_names,1),Date=datetime,ID=1,User=user_to_manipulate,Source=sources_names[1],Source_Port=0,Logon_Type=2))
    }
  }
}

## Untypische Nutzerzeiten, Version 3

#AM wocheende aktiv ein Event ein Tag
testset<-rbind(testset,data.frame(Event_Typ=4624,Host=sample(workstations_names,1),Date=as_datetime("2021-06-13 08:00:00 UTC"),ID=1,User=user_to_manipulate,Source=sources_names[1],Source_Port=0,Logon_Type=2))

#An einem Wocheend Tag, aber mehrere Events
for(i in 1:50){
  datetime<-as_datetime(as_datetime("2021-06-13 00:00:01 UTC")+minutes(i*15))
  testset<-rbind(testset,data.frame(Event_Typ=4624,Host=workstations_names[1],Date=datetime,ID=1,User=user_to_manipulate,Source=sources_names[1],Source_Port=0,Logon_Type=2))
}

#An mehreren Wocheendtagen
for(j in 1:14){
  date<-as_datetime("2021-06-15 00:00:00 UTC")+days(j)
  if(wday(date)==6 || wday(date)==7){
    freq<-sample(30:70,1)
    for(i in 1:freq){
      datetime<-as_datetime(date+minutes(i*15))
      testset<-rbind(testset,data.frame(Event_Typ=4624,Host=workstations_names[1],Date=datetime,ID=1,User=user_to_manipulate,Source=sources_names[1],Source_Port=0,Logon_Type=2))
    }
  }
}

#An mehreren Wocheendtagen nicht hintereinander
for(j in 1:14){
  date<-as_datetime("2021-06-15 00:00:00 UTC")+days(j)
  active<-sample(c(1,0),1,prob=c(0.65,0.35))
  if(wday(date)==6 || wday(date)==7){
    if(active==1){
      freq<-sample(30:70,1)
      for(i in 1:freq){
        datetime<-as_datetime(date+minutes(i*15))
        testset<-rbind(testset,data.frame(Event_Typ=4624,Host=sample(workstations_names,1),Date=datetime,ID=1,User=user_to_manipulate,Source=sources_names[1],Source_Port=0,Logon_Type=2))
      } 
    }
  }
}

# Ein Event außerhalb der gewöhnlichen Arbeitszeit
testset<-rbind(testset,data.frame(Event_Typ=4624,Host=workstations_names[1],Date="2021-06-15 23:01:02 UTC",ID=1,User=user_to_manipulate,Source=sources_names[1],Source_Port=0,Logon_Type=2))

#Mehrere Events außerhalb der gewöhnlichen Arbeitszeit
for(i in 1:40){
  date<-as_datetime(as_datetime("2021-06-15 23:00:00 UTC")+minutes(i*2))
  testset<-rbind(testset,data.frame(Event_Typ=4624,Host=workstations_names[1],Date=date,ID=1,User=user_to_manipulate,Source=sources_names[1],Source_Port=0,Logon_Type=2))
}

#Mehrere Events, außerhalb der Arbeitszeit an mehreren Tagen
for(j in 1:10){
  date<-as_datetime("2021-06-15 22:00:00 UTC")+days(j)
  if(wday(date)!=6 && wday(date)!=7){
    freq<-sample(30:70,1)
    for(i in 1:freq){
      datetime<-as_datetime(date+minutes(i*15))
      testset<-rbind(testset,data.frame(Event_Typ=4624,Host=workstations_names[1],Date=datetime,ID=1,User=user_to_manipulate,Source=sources_names[1],Source_Port=0,Logon_Type=2))
    }
  }
}

# Ein Event außerhalb der Arbeitszeit aller zwei Stunde beginn 16:00
n<-0
for (i in seq(0,16,2)){
  n<-n+1
  x<-rbind(testset,data.frame(Event_Typ=4624,Host=3779310,Date=as_datetime("2021-06-15 16:00:01 UTC")+hours(i),ID=1,User=user_to_manipulate,Source=sources_names[1],Source_Port=0,Logon_Type=2))
  write.table(x,paste("/home/rmey/Dokumente/my_projekt/Testset/Version_3_Testcase_9_",n,".csv",sep=""),row.names = F,col.names = F,sep=",")
}



##Verhaltenswechsel von Interactive zu Remote

#Ein Remote Event
testset<-testset[!(testset$User==user_to_manipulate & date(testset$Date)=="2021-06-15"),]
datetime<-as_datetime("2021-06-15 08:02:02 UTC")
testset<-rbind(testset,data.frame(Event_Typ=4624,Host=workstations_names[1],Date=datetime,ID=1,User=user_to_manipulate,Source=sources_names[1],Source_Port=0,Logon_Type=2))

datetime<-as_datetime("2021-06-15 11:02:02 UTC")
testset<-rbind(testset,data.frame(Event_Typ=4624,Host=workstations_names[1],Date=datetime,ID=1,User=user_to_manipulate,Source=sources_names[2],Source_Port=49992,Logon_Type=10))

#Mehrere Remotes ein Tag
testset<-testset[!(testset$User==user_to_manipulate & date(testset$Date)=="2021-06-15"),]
datetime<-as_datetime("2021-06-15 08:02:02 UTC")
testset<-rbind(testset,data.frame(Event_Typ=4624,Host=workstations_names[1],Date=datetime,ID=1,User=user_to_manipulate,Source=sources_names[1],Source_Port=0,Logon_Type=2))

for(i in 1:20){
  datetime<-as_datetime("2021-06-15 10:02:02 UTC")+minutes(sample(1:420,1))
  testset<-rbind(testset,data.frame(Event_Typ=4624,Host=workstations_names[2],Date=datetime,ID=1,User=user_to_manipulate,Source=sources_names[2],Source_Port=sample(c(1024:65534),1),Logon_Type=10))
}

# Nutzer ist zwei Wochen weg

testset<-testset[!(testset$User==user_to_manipulate & testset$Date>=as.Date("2021-06-14 00:00:00 UTC") & testset$Date <=as.Date("2021-06-27 23:59:59 UTC")),]

# Alle Nutzer fallen weg einer bleibt da an einem Tag
`%notin%` <- Negate(`%in%`)
testset<-testset[!(testset$User %notin% (user_to_manipulate) & testset$Date>=as.Date("2021-06-14 00:00:00 UTC") & testset$Date<as.Date("2021-06-15 00:00:00 UTC")),]

# Zeitumstellung aller Nutzer ab dem 28.06 annahme es exsitieren zwei Standorte eine in dd (~30%)

german_location_workers<-sample(users_names_normal,30)
needs_rework<-testset[testset$User %in% german_location_workers & testset$Date >=as.Date("2021-06-28 00:00:00 UTC"),]
testset<-testset[!(testset$User %in% german_location_workers & testset$Date >=as.Date("2021-06-28 00:00:00 UTC")),]

for(i in 1:nrow(needs_rework)){
  needs_rework[i,3]<-as_datetime(needs_rework[i,3])+hours(1)
}

testset<-rbind(testset,needs_rework)

write.table(data.frame(german_location_workers),"/home/rmey/Dokumente/my_projekt/Testset/Version_3_Testcase_16_german_workers.csv",row.names = F,col.names = F,sep=",")

# Auswerten dessen

result<-read.csv("/home/rmey/Dokumente/FindMaliciousEvents_235/Ergebnisse.csv")
result_without_manipulation<-read.csv("/home/rmey/Dokumente/FindMaliciousEvents_232/Ergebnisse.csv")
workers<-read.csv("/home/rmey/Dokumente/my_projekt/Testset/Version_3_Testcase_16_german_workers.csv",header = F)
result[,1]<-sub("^X","",sub("\\.[0-9]*$","",result[,1]))
result_without_manipulation[,1]<-sub("^X","",sub("\\.[0-9]*$","",result_without_manipulation[,1]))

position<-data.frame()
for(i in 1:nrow(workers)){
  position[i,1]<-which(result$X==workers[i,1])-which(result_without_manipulation$X==workers[i,1])
}
colMeans(position)

# Nutzer wechselt vollständig ins Home-Office ab dem 05.06.2021
testset<-testset[!(testset$User==user_to_manipulate & testset$Date>=as.Date("2021-06-05 00:00:00 UTC")),]

for (i in 5:days) {
  
  date<-as_datetime("2021-05-31")+days(i)
  
  mid_day<-F
  
  
  if(wday(date)!=6 && wday(date)!=7){
    workstart<-rnorm(1,mean=28800,sd=600)
    testset<-rbind(testset,data.frame(Event_Typ=4624,Host=workstations_names[2],Date=as_datetime(date+seconds(workstart)),ID=1,User=user_to_manipulate,Source=sources_names[2],Source_Port=sample(c(1024:65534),1),Logon_Type=10))
    first_time<-F
    mid_day<-T
    
    lunchstart<-rnorm(1,mean=45000,sd=1800)
    lunchtime<-rnorm(1,mean = 1800,sd=300)
    lunchend<-lunchstart+lunchtime
    testset<-rbind(testset,data.frame(Event_Typ=4624,Host=workstations_names[2],Date=as_datetime(date+seconds(lunchend)),ID=1,User=user_to_manipulate,Source=sources_names[2],Source_Port=sample(c(1024:65534),1),Logon_Type=10))
    
    worktime<-rnorm(users,mean=28800,sd=300)
    workend<-workstart+worktime

    for(j in 1:1){
      breaks<-round(rnorm(1,mean=5,sd=2),digits = 0)
      if(breaks>0){
        break_time<-sample(c(workstart[j]:lunchstart[j],lunchend[j]:workend[j]),breaks)
        testset<-rbind(testset,data.frame(Event_Typ=4624,Host=workstations_names[2],Date=as_datetime(date+seconds(break_time)),ID=1,User=user_to_manipulate,Source=sources_names[2],Source_Port=sample(c(1024:65534),1),Logon_Type=10))
      }
    }
  }
  
}


## EIn User wird zweifach verwendet ab dem 15.06.2021, nur zur hälfte in der Arbeitszeit, gleich zu den vorher Nutzer aktivitäten, nicht am WE
user_to_manipulate<-4346631
for (i in 15:days) {
  
  date<-as_datetime("2021-05-31")+days(i)
  
  mid_day<-F
  
  
  if(wday(date)!=6 && wday(date)!=7){
    workstart<-rnorm(1,mean=43200,sd=600)
    testset<-rbind(testset,data.frame(Event_Typ=4624,Host=workstations_names[2],Date=as_datetime(date+seconds(workstart)),ID=1,User=user_to_manipulate,Source=sources_names[2],Source_Port=sample(c(1024:65534),1),Logon_Type=10))
    first_time<-F
    mid_day<-T
    
    lunchstart<-rnorm(1,mean=57600,sd=1800)
    lunchtime<-rnorm(1,mean = 1800,sd=300)
    lunchend<-lunchstart+lunchtime
    testset<-rbind(testset,data.frame(Event_Typ=4624,Host=workstations_names[2],Date=as_datetime(date+seconds(lunchend)),ID=1,User=user_to_manipulate,Source=sources_names[2],Source_Port=sample(c(1024:65534),1),Logon_Type=10))
    
    worktime<-rnorm(users,mean=28800,sd=300)
    workend<-workstart+worktime
    
    for(j in 1:1){
      breaks<-round(rnorm(1,mean=5,sd=2),digits = 0)
      if(breaks>0){
        break_time<-sample(c(workstart[j]:lunchstart[j],lunchend[j]:workend[j]),breaks)
        testset<-rbind(testset,data.frame(Event_Typ=4624,Host=workstations_names[2],Date=as_datetime(date+seconds(break_time)),ID=1,User=user_to_manipulate,Source=sources_names[2],Source_Port=sample(c(1024:65534),1),Logon_Type=10))
      }
    }
    
    network<-round(rnorm(1,mean=5,sd=2),digits = 0)
    if(network>0){
      break_time<-sample(c(workstart[j]:lunchstart[j],lunchend[j]:workend[j]),network)
      testset<-rbind(testset,data.frame(Event_Typ=4624,Host=sample(workstations_names,network),Date=as_datetime(date+seconds(break_time)),ID=1,User=user_to_manipulate,Source=sources_names[2],Source_Port=sample(c(1024:65534),1),Logon_Type=3))
    }
    
  }
  
}


## Alle Hosts haben ab dem 15.06 einen neuen Nutzer mehr mit dem Event Typ 3 mit einem Event typ 3
user_to_manipulate<-1234567

for(i in 15:days){
  date<-as_datetime("2021-05-31")+days(i)
  for(j in workstations_names){
    date<-as_datetime(date+seconds(sample(0:86399,1)))
    testset<-rbind(testset,data.frame(Event_Typ=4624,Host=j,Date=date,ID=1,User=user_to_manipulate,Source=sources_names[2],Source_Port=sample(c(1024:65534),1),Logon_Type=3))
  }
}

result_without<-read.csv("/home/rmey/Dokumente/FindMaliciousEvents_351/Ergebnisse.csv")
result_with<-read.csv("/home/rmey/Dokumente/FindMaliciousEvents_356/Ergebnisse.csv")
  

result_without[,1]<-data.frame(Identifier=sub("^X","",sub("\\.[0-9]*$","",result_without[,1])))
result_with[,1]<-data.frame(Identifier=sub("^X","",sub("\\.[0-9]*$","",result_with[,1])))

diff<-data.frame()
for(i in 1:nrow(result_with)){
  diff[i,1]<-abs(result_with[i,ncol(result_with)]) - abs(result_without[result_without$X==result_with[i,1],ncol(result_without)])
}
colMeans(diff)

write.table(testset,"/home/rmey/Dokumente/my_projekt/Testset/Version_3_Testcase_19_v1.csv",row.names = F,col.names = F,sep=",")
