#!/usr/bin/Rscript --vanilla
#https://www.r-bloggers.com/2019/11/r-scripts-as-command-line-tools/

# Module:            Bachelor thesis
# Theme:             Detect Malicious Login Events
# Author:            Richard Mey <richard.mey@syss.de>
# Status:            25.06.2021

###########
# Comment #
###########

# Duration depends on:
#   Number of events in the selected period
#   Size of the selected period
#   Depends on the perspective  how many Users/Hosts/Sources are contained
#   Used machine learning method

#####################
# Command arguments #
#####################

# Loading arguments from command line
args <- commandArgs()

# Set the path to the R site packages
.libPaths("~/.R")

#################
# Main Function #
#################

main <- function(args) {

  # Check if the arguments are empty, if yes top else split them
  if (length(args[(grep("--args", args))]) == 0) { # TODO=refactor into function
    stop("You need to hand over a dataset.", call. = F)
  }else {
    envr_args <- args[1:grep("--args", args)]
    args <- args[(grep("--args", args) + 1):length(args)]
  }

  if (args[1] == "--help") {
    help_output()
  }else if (file.exists(args[1]) == F) {
    stop("The file needs to exist.", call. = F) # TODO=Datenpfad
  }else if (dir.exists(args[2]) == F) {
    stop("The directory needs to exists.", call. = F)
  }else {

    if (file.access(as.character(args[2]), c(4, 2)) == -1) { # TODO=Vektor bennen
      stop("Enter a location where you got the sufficient rights (w,r).", call. = F) # TODO=Schreiben was falsch ist
    }
    load_libraries()
    path <- create_output_folder(args)
    parsed_arguments <- parse_arguments(args, envr_args)
    parsed_arguments$path <- path
    features <- extract_features_from_file(parsed_arguments)
    anomaly_detection(features, parsed_arguments)

    if (parsed_arguments$with_plots) {
      visualization_results(features, path, parsed_arguments$group, parsed_arguments$rank, parsed_arguments$mean_rank)
    }

    cat("Done.", fill = 1)

  }

}

#################
# Help Function #
#################

#Falls die Option --help Angeben wird, wird folgender Text auf der Konsole ausgegeben

help_output <- function() {
  cat("Usage: FindMaliciousEvents [file] [dir] [--options]",
      "Currently supported file formats are: csv. The File needs the following construction (Event ID, Host, Time, Logon ID, User, Source, Source Port, Logon Type).",
      "Options:",
      "",
      "--help    Help output",
      "-oa       Gives overall statictics to given data",
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
      "          RF Randomforest - special to rank is the only option",
      "-p        Use this to limit your cores to use. The next argument should be the logical count of cores to use, default is cores-1",
      "-r        The output will be a complet ranked list, default principle is first comes first",
      "          m If you want to get it mean ranked ",
      "-s        Save the trained model",
      "-lm       The next argument should be the path to the directory with the trained model information",
      "-n        Plots will not be generated", fill = 2)
}


# Creates new Folder with _X
create_output_folder <- function(args) {
  tryCatch(expr = {
    path <- paste(as.character(args[2]), "/FindMaliciousEvents_1/", sep = "")
    if (dir.exists(path) == F) {
      dir.create(path)
    }else {
      dir <- list.dirs(as.character(args[2]), recursive = F, full.names = F)
      dir_ME <- grep("FindMaliciousEvents_[0-9]+", dir)
      path <- paste(as.character(args[2]), "/FindMaliciousEvents_", (max(as.numeric(sub("[^0-9]+", "", dir[dir_ME]))) + 1), "/", sep = "")
      dir.create(path)
    }
    return(path)
  }, warning = function(w) {
  }, finally = {
  })
}

#########
# Setup #
#########

# function to load and activate all needed libraries
load_libraries <- function() {
  # Download path to libraries
  repos <- "https://cran.r-project.org/"

  ## Install all needed libraries
  #https://stackoverflow.com/questions/9341635/check-for-installed-packages-before-running-install-packages
  packages <- c("tidyr", "dplyr", "ggplot2", "tools", "lubridate", "doParallel", "reshape2", "scales", "FactoMineR", "factoextra", "R.utils", "reticulate", "RColorBrewer", "fmsb", "BBmisc", "ranger", "caret", "e1071", "clue")
  suppressMessages(install.packages(setdiff(packages, rownames(installed.packages())), repos = repos, quiet = T))


  # Load all libraries
  suppressMessages(library(tidyr))
  suppressMessages(library(tools))
  suppressMessages(library(dplyr))
  suppressMessages(library(ggplot2))
  suppressMessages(library(lubridate, quietly = T, mask.ok = F))
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


  # Options
  options(lubridate.week.start = 1) #weekday starts monday
  options("scipen" = 10)
  Sys.setenv(TZ = 'UTC')
  pdf(NULL)
}

# Function to parse Arguments from command line
parse_arguments <- function(args, envr_args) {
  parsed_arguments <- list()
  parsed_arguments$data_path <- data_path_argument(args)
  parsed_arguments$statistics <- statistics_argument(args)
  parsed_arguments$view <- view_argument(args)
  ml_and_group <- machine_learning_argument(args)
  parsed_arguments$ml <- ml_and_group$ml
  parsed_arguments$group <- ml_and_group$group
  time_arguments <- time_bin_argument(args)
  parsed_arguments$time_bin <- time_arguments$time_bin
  parsed_arguments$time_bin_size <- time_arguments$time_bin_size
  parsed_arguments$days_instead <- time_arguments$days_instead
  time_windows <- time_window_argument(args)
  parsed_arguments$startdate <- time_windows$startdate
  parsed_arguments$enddate <- time_windows$enddate
  parsed_arguments$completely <- time_windows$completely
  rank_argsuments <- rank_argument(args)
  parsed_arguments$rank <- rank_argsuments$rank
  parsed_arguments$mean_rank <- rank_argsuments$mean_rank
  parsed_arguments$cores <- cores_argument(args)
  loaded_model <- load_model_argument(args)
  parsed_arguments$load_model <- loaded_model$load_model
  parsed_arguments$model_path <- loaded_model$model_path
  parsed_arguments$save_model <- save_model_argument(args)
  parsed_arguments$with_plots <- with_plots_argument(args)
  parsed_arguments$extracted_features <- extracted_features_argument(args)
  parsed_arguments$absolute_path <- location_script(envr_args)
  return(parsed_arguments)
}

# Return Data path
data_path_argument <- function(args) {
  return(as.character(args[1]))
}

# Return statistics argument
statistics_argument <- function(args) {

  statistics <- F

  if (length(grep("-oa", as.character(args))) != 0) {
    statistics <- T
  }
  return(statistics)
}

# Return vview argument
view_argument <- function(args) {

  view <- 4

  if (length(grep("-v", as.character(args))) != 0) {
    if (is.na(args[grep("-v", as.character(args)) + 1])) {
      stop("Choose one of the point of views as option (u,h,s).", call. = F)
    }else {
      if (as.character(args[grep("-v", as.character(args)) + 1]) == "u" ||
        as.character(args[grep("-v", as.character(args)) + 1]) == "h" ||
        as.character(args[grep("-v", as.character(args)) + 1]) == "s") {
        if (as.character(args[grep("-v", as.character(args)) + 1]) == "u") {
          view <- 4
        }else if (as.character(args[grep("-v", as.character(args)) + 1]) == "h") {
          view <- 2
        }else {
          view <- 5
        }
      }else {
        stop("Choose one of the valid point of views as option  (u,h,s).", call. = F)
      }
    }
  }
  return(view)
}

# Return ml arguments
machine_learning_argument <- function(args) {

  ml <- "IF"
  group <- T

  if (length(grep("-m", as.character(args))) != 0) {
    if (is.na(args[grep("-m", as.character(args)) + 1])) {
      stop("Choose one of the machine learning options (IF,kNN,DAGMM,RF).", call. = F)
    }else {
      if (as.character(args[grep("-m", as.character(args)) + 1]) == "IF" ||
        as.character(args[grep("-m", as.character(args)) + 1]) == "kNN" ||
        as.character(args[grep("-m", as.character(args)) + 1]) == "DAGMM" ||
        as.character(args[grep("-m", as.character(args)) + 1]) == "RF") {
        if (as.character(args[grep("-m", as.character(args)) + 1]) == "IF") {
          ml <- "IF"
        }else if (as.character(args[grep("-m", as.character(args)) + 1]) == "kNN") {
          ml <- "kNN"
        }else if (as.character(args[grep("-m", as.character(args)) + 1]) == "DAGMM") {
          ml <- "DAGMM"
        }else {
          ml <- "RF"
          group <- F
        }
      }else {
        stop("Choose one of the valid machine learning options (IF,kNN,DAGMM,RF).", call. = F)
      }
    }
  }
  return(list(ml = ml, group = group))
}

# Return time bin arguments
time_bin_argument <- function(args) {

  time_bin <- "d"
  time_bin_size <- 0
  days_instead <- F

  if (length(grep("-t", as.character(args))) != 0) {
    if (is.na(args[grep("-t", as.character(args)) + 1])) {
      stop("Choose one of the time slot options (d,h,dh).", call. = F)
    }else {
      if (as.character(args[grep("-t", as.character(args)) + 1]) == "h" ||
        as.character(args[grep("-t", as.character(args)) + 1]) == "d" ||
        as.character(args[grep("-t", as.character(args)) + 1]) == "dh") {
        if (as.character(args[grep("-t", as.character(args)) + 1]) == "d") {
          time_bin <- "d"
          if (is.na(args[grep("-t", as.character(args)) + 2]) == F && length(grep("-", args[grep("-t", as.character(args)) + 2])) == F) {
            if (as.character(args[grep("-t", as.character(args)) + 2]) == "d") {
              days_instead <- T
            }else {
              stop("The only option you can use here is d.", call. = F)
            }
          }
        }else {
          if (as.character(args[grep("-t", as.character(args)) + 1]) == "h") {
            time_bin <- "h"
          }else {
            time_bin <- "dh"
          }

          if (is.na(args[grep("-t", as.character(args)) + 2]) == F && length(grep("-", args[grep("-t", as.character(args)) + 2])) == F) {
            if (length(grep("^[0-9]*$", as.character(args[grep("-t", as.character(args)) + 2]))) != 0) {
              time_bin_size <- as.numeric(args[grep("-t", as.character(args)) + 2]) - 1
              if (time_bin_size < 0 || time_bin_size > 71) {
                stop("Please insert a number of hours bigger then 0 and smaller then 73.", call. = F)
              }
            }else {
              stop("Please insert a number behind the hour/day-hour time bin format.", call. = F)
            }
          }else {
          }
        }
      }else {
        stop("Choose one of the valid time slot options (d,h,dh).", call. = F)
      }
    }
  }
  return(list(time_bin = time_bin, time_bin_size = time_bin_size, days_instead = days_instead))
}

# Return rank arguments
rank_argument <- function(args) {
  rank <- F
  mean_rank <- F
  if (length(grep("-r", as.character(args))) != 0) {
    if (is.na(args[grep("-r", as.character(args)) + 1]) != T && length(grep("-", args[grep("-r", as.character(args)) + 1])) == F) {
      if (as.character(args[grep("-r", as.character(args)) + 1]) == "m") {
        mean_rank <- T
      }else {
        stop("Choose one of the valid rank ptions (m).", call. = F)
      }
    }
    rank <- T
  }
  return(list(rank = rank, mean_rank = mean_rank))
}

# Return time window argument
time_window_argument <- function(args) {
  completely <- F
  if (length(grep("-d", as.character(args))) != 0) {
    if (is.na(args[grep("-d", as.character(args)) + 1])) {
      stop("Choose an option for start- and enddate (m,v).", call. = F)
    }else {
      if (as.character(args[grep("-d", as.character(args)) + 1]) == "m" || as.character(args[grep("-d", as.character(args)) + 1]) == "v") {
        if (as.character(args[grep("-d", as.character(args)) + 1]) == "m") {
          if (is.na(args[grep("-d", as.character(args)) + 2]) && is.na(args[grep("-d", as.character(args)) + 3])) {
            stop("Hand over a start- and enddate.", call. = F)
          }else {
            tryCatch(expr = {
              startdate <- as_date(args[grep("-d", as.character(args)) + 2])
              enddate <- as_date(args[grep("-d", as.character(args)) + 3])
            }, warning = function(w) {
              stop("Hand over a valid start- and enddate.", call. = F)
            })
            if (startdate > enddate) {
              stop("Your startdate is older then the enddate, change the information.", call. = F)
            }
          }
        }else {
          completely <- T
        }
      }else {
        stop("Choose a valid option for the start- and enddate (m,v).", call. = F)
      }
    }
  }else {
    startdate <- NULL
    enddate <- NULL
  }
  return(list(startdate = startdate, enddate = enddate, completely = completely))
}

# Return core argument
cores_argument <- function(args) {
  if (length(grep("-p", as.character(args))) != 0) {
    if (is.na(args[grep("-p", as.character(args)) + 1])) {
      stop("Hand over a number of logical processors to use.", call. = F)
    }else {
      tryCatch(expr = {
        cores <- as.numeric(args[grep("-p", as.character(args)) + 1])
        if (cores > detectCores()) {
          stop("You can´t use a bigger number of logicals processors then available.", call. = F)
        }else if (cores < 1) {
          stop("You can´t use a smaller number of logicals processors then one.", call. = F)
        }
      }, warning = function(w) {
        stop("Insert a number of cores, based on your processor.", call. = F)
      })
    }
  }else {
    cores <- detectCores() - 1
  }
  return(cores)
}

# Return load model arguemnts
load_model_argument <- function(args) {
  if (length(grep("-lm", as.character(args))) != 0) {
    if (is.na(args[grep("-lm", as.character(args)) + 1])) {
      stop("You need to hand over a path to the directory with the model information.", call. = F)
    }else {
      model_path <- as.character(args[grep("-lm", as.character(args)) + 1])
      if (dir.exists(model_path) == F) {
        stop("You need to hand over an existing model directory.", call. = F)
      }
      if (file.exists(paste(model_path, "cluster.rds", sep = "")) == F ||
        (file.exists(paste(model_path, "min_max.rds", sep = "")) == F && ml != "RF") ||
        (file.exists(paste(model_path, "model.joblib", sep = "")) == F &&
          file.exists(paste(model_path, "model.rds", sep = "")) == F &&
          file.exists(paste(model_path, "model.index", sep = "")) == F)) {
        stop("Hand over a directory that contains the following content: (min_max.rds), cluster.rds, model.(rds/joblib/index). ", call. = F)
      }

      if ((file.exists(paste(model_path, "model.rds", sep = "")) == F && ml == "RF") ||
        (file.exists(paste(model_path, "model.rds", sep = "")) == T && (ml == "IF" || ml == "kNN")) ||
        (file.exists(paste(model_path, "model.index", sep = "")) == F && ml == "DAGMM")) {
        stop("Use the correct model on load with the correct machine learning option.", call. = F)
      }
      load_model <- T
    }
  }else {
    model_path <- ""
    load_model <- F
  }
  return(list(load_model = load_model, model_path = model_path))
}

# Return save model argument
save_model_argument <- function(args) {
  if (length(grep("-s", as.character(args))) != 0) {
    save_model <- T
    dir.create(paste(path, "model/", sep = ""))
  }else {
    save_model <- F
  }
  return(save_model)
}

# With out plots argument
with_plots_argument <- function(args) {
  if (length(grep("-n", as.character(args))) != 0) {
    with_plots <- F
  }else {
    with_plots <- T
  }
  return(with_plots)
}

# Extracted Feature Argument
extracted_features_argument <- function(args) {
  if (length(grep("-e", as.character(args))) != 0) {
    extracted_features <- T
  }else {
    extracted_features <- F
  }
  return(extracted_features)
}

# Main Function to generate or read Features
extract_features_from_file <- function(parsed_arguments) {
  if (parsed_arguments$extracted_features) {
    features <- features_read_in(parsed_arguments$path)
  }else {
    data <- read_in(parsed_arguments$data_path, parsed_arguments$path)
    if (is.null(nrow(data)) == F) {
      features <- extract_features(data, parsed_arguments)
    }else {
      if (is.null(parsed_arguments$startdate) == T && parsed_arguments$completely == F) {
        stop("If the file is to large, hand over a start- and enddate.", call. = F)
      }
      # TODO=loop{edges,extract features)
      features <- feature_extraction_parted_from_file(parsed_arguments)
    }
  }
  return(features)
}

# If the option -e has been choosen, Features which has been created with this program can be loaded
features_read_in <- function(path) {
  if (file_ext(path) == "csv") {
    if (file.access(path, 2) == -1) {
      stop("Enter a file for which you got the rights to read.", call. = F)
    }
    tryCatch(expr = {
      features <- read.csv(path, row.names = 1)
      if (length(grep("weekday|number_events|Proportion_[0-9_]+|hour|day|events_per_second|Identifier|Users_per_Host|Users_per_Source|Hosts_per_User|Hosts_per_Source|Sources_per_User|Sources_per_Host", colnames(features), invert = T)) != 0) {
        stop("The inserted Feature set, does not match the feature the programs generate.", call. = F)
      }
      return(features)
    }, error = function(e) {
      stop("Provide a valid, non-empty file.", call. = F)
    }, warning = function(w) {
    })

  }else {
    stop("The specified file needs to match with one of the acceptable file formats (csv).", call. = F)
  }
}

# Read raw data
read_in <- function(data_path, path) {
  # R loads all data in the memory, so if the raw data it cant read all without crashing, thats why it can be splited read in
  # Read in free memory
  mem <- get_free_memory()

  # Read in data file size
  size <- as.numeric(file.info(data_path)$size) / 1000000

  # End program if its not csv
  if (file_ext(data_path) == "csv") {
    # If the user dont got enough rights, end
    if (file.access(data_path, 2) == -1) {
      stop("Enter a file for which you got the rights to read.", call. = F)
    }

    # If the raw data file, occupied more than 40% of the memory -> parted read in
    if (size >= mem * 0.4) {
      cat("The specified file is too large, hence the read-in/ preprocessing/ feature extraction will be splited. This process might take more time.", fill = 2)
      split <- T
      # To let the features be complety, sort it by time
      system(paste("sort -k3 -t, ", data_path, " >> ", path, "time_sort.csv", sep = ""))
      return(split)
    }else {
      # <40% read data
      tryCatch(expr = {
        data <- read.csv(data_path, colClasses = c("integer", "numeric", "POSIXct", "numeric", "numeric", "numeric", "integer", "integer"), header = F)
      }, error = function(e) {
        stop("Provide a valid, non-empty file and in accordance with the format: Int,Num,Date,Num,Num,Num,Int,Int.", call. = F)
      }, warning = function(w) {
        stop("The file needs the following columns: Event_ID,Host,Time,Logon_ID,User,Source,Source Port,Logon Typ.", call. = F)
      })

      # If the data is smaller than 1000 rows, the program will stop working, because its too less
      if (nrow(data) < 1000) {
        stop("The file contains fewer then 1000 rows. You should use one with more.", call. = F)
      }

      # Rename columns and delet all Events that dont fit to 4624
      colnames(data) <- c("Event_ID", "Host", "Time", "Logon_ID", "User", "Source", "Source_Port", "Logon_Type") #ActivityID oder LogonGUID
      data <- data[(data$Event_ID == 4624),]
      return(data)
    }

  }else {
    stop("The specified file needs to match with one of the acceptable file formats (csv).", call. = F)
  }

}

# Get the free memory
get_free_memory <- function() {
  mem <- system('free -m', intern = T)
  mem <- strsplit(mem, " ")
  mem <- as.numeric(tail(mem[[2]], n = 1))
  return(mem)
}

# If the file size is to large, read it in parts
parted_read_in <- function(path, row_multi, back) {
  tryCatch(expr = {
    # read in x rows and skip all before
    data_new <- read.csv(paste(path, "time_sort.csv", sep = ""), nrows = 10000000, skip = (row_multi * 10000000) - back, colClasses = c("integer", "numeric", "POSIXct", "numeric", "numeric", "numeric", "integer", "integer"), header = F)
    colnames(data_new) <- c("Event_ID", "Host", "Time", "Logon_ID", "User", "Source", "Source_Port", "Logon_Type") #ActivityID oder LogonGUID
    data_new <- data_new[(data_new$Event_ID == 4624),]
    return(data_new)
  }, error = function(e) {
    if (row_multi == 0) {
      stop("Provide a valid, non-empty file and in accordance with the format: Int,Num,Date,Num,Num,Num,Int,Int.", call. = F)
    }else {
      finished <- T
      return(finished)
    }
  }, warning = function(w) {
    stop("The file needs the following columns: Event_ID,Host,Time,Logon_ID,User,Source,Source Port,Logon Typ.", call. = F)
  })
}

# Feature extraction without splitting data before
extract_features <- function(data, parsed_arguments) {
  # If statistics is true do pre and post statistics
  if (parsed_arguments$statistics) {
    path_statistics_before <- paste(parsed_arguments$path, "Datenanalyse_vor/", sep = "")
    dir.create(path_statistics_before)
    border <- data_statistics(data, path_statistics_before)
  }

  # Do preprocessing
  data <- preprocessing(data)

  if (parsed_arguments$statistics) {
    path_statistics_after <- paste(parsed_arguments$path, "Datenanalyse_nach/", sep = "")
    dir.create(path_statistics_after)
    border <- data_statistics(data, path_statistics_after)
  }

  # Control the start- and enddate, if no dates are given calculate some
  if (is.null(parsed_arguments$startdate)) {
    if (parsed_arguments$completely) {
      parsed_arguments$startdate <- as_date(min(data$Time))
      parsed_arguments$enddate <- as_date(max(data$Time))
    }else {
      if (parsed_arguments$statistics) {
        parsed_arguments$startdate <- border[[1]]
        parsed_arguments$enddate <- border[[2]]
      }else {
        timeline <- timeline_month(data)
        border <- calc_borders(timeline)
        parsed_arguments$startdate <- border[[1]]
        parsed_arguments$enddate <- border[[2]]
      }
    }
  }

  if (nrow(data[(data$Time >= (as.Date(parsed_arguments$startdate)) & (data$Time < (as.Date(parsed_arguments$enddate)))),]) == 0) {
    stop("Insert a start- and enddate, that fits to the data.", call. = F)
  }

  features <- feature_extraction(data, parsed_arguments)
  write.csv(features, paste(parsed_arguments$path, "Features.csv", sep = ""))

  return(features)
}

# Feature extraction in parts
feature_extraction_parted_from_file <- function(parsed_arguments) {

  finished <- F
  row_multi <- 0
  back <- 0
  features <- data.frame()
  completely <- parsed_arguments$completely

  # Read-in data until its 
  while (finished == F) {
    data <- parted_read_in(parsed_arguments$path, row_multi, back)

    if (is.null(nrow(data)) == F) {

      optimized_date <- optimize_date(data, parsed_arguments)
      finished <- optimized_date$finished

      row_multi <- row_multi + 1 # TODO=start or end

      # If data contains date interval, that doesnt fit to start and enddate, ignore it
      if (optimized_date$ignore == F) { # TODO=ignore_date
        parted_feature_result <- parted_feature_extraction(data, finished, optimized_date$parsed_arguments, back, row_multi)
        finished <- parted_feature_result$finished
        back <- parted_feature_result$back
        features <- rbind(features, parted_feature_result$features)
      }
      rm(data)
    }else {
      finished <- T
    }
  }

  if (is.null(features[1, 1])) {
    stop("Insert a start- and enddate, that fits to the data.", call. = F)
  }

  if (parsed_arguments$group == T) {
    features <- group_features(features, parsed_arguments$view, parsed_arguments$time_bin, parsed_arguments$cores, load_model = parsed_arguments$load_model, model_path = parsed_arguments$model_path, save_model = parsed_arguments$save_model, path = parsed_arguments$path)
  }
  write.csv(features, paste(parsed_arguments$path, "Features.csv", sep = ""))

  return(features)
}

# Optimize date on parted Feature extraction
optimize_date <- function(data, parsed_arguments) {

  finished <- F
  ignore <- F

  if (parsed_arguments$completely != T) {

    enddate_optimized <- parsed_arguments$enddate
    startdate_optimized <- parsed_arguments$startdate

    if (startdate_optimized > as_date(max(data$Time))) {
      ignore <- T
    }else if (enddate_optimized < as_date(min(data$Time))) {
      finished <- T
      ignore <- T
    }else if (enddate_optimized > as_date(max(data$Time))) {
      enddate_optimized <- as_date(max(data$Time))
    }
    if (as_date(min(data$Time)) > startdate_optimized) {
      startdate_optimized <- as_date(min(data$Time))
    }
  }else {
    enddate_optimized <- as_date(max(data$Time))
    startdate_optimized <- as_date(min(data$Time))
  }

  parsed_arguments$startdate <- startdate_optimized
  parsed_arguments$enddate <- enddate_optimized

  return(list(parsed_arguments = parsed_arguments, ignore = ignore, finished = finished))
}

# Function to check how many steps to go back and to do feature extraction 
parted_feature_extraction <- function(data, optimized_arguments, back, row_multi) {
  time_bin <- optimized_arguments$time_bin
  path <- optimized_arguments$path
  time_bin_size <- optimized_arguments$time_bin_size

  tryCatch(expr = {
    check <- read.csv(paste(path, "time_sort.csv", sep = ""), nrows = 1, skip = (row_multi * 10000000) - back + 1, colClasses = c("integer", "numeric", "POSIXct", "numeric", "numeric", "numeric", "integer", "integer"), header = F, col.names = c("Event_ID", "Host", "Time", "Logon_ID", "User", "Source", "Source_Port", "Logon_Type"))
    if (date(data[nrow(data), 3]) == date(check[1, 3]) && time_bin == "d") {
      data <- data[!(date(data$Time) == date(check[1, 3])),]
      # }else if(((as_datetime(data[nrow(data),3])-hours(time_bin_size+1))>=as_datetime(check[1,3])) && hour(data[nrow(data),3])==hour(check[1,3]) && (time_bin=="dh" || time_bin=="h") && optimized_arguments$time_bin_size>0){
      #  data<-data[!(as_datetime(data$Time>=))]
    }else if (date(data[nrow(data), 3]) == date(check[1, 3]) &&
      hour(data[nrow(data), 3]) == hour(check[1, 3]) &&
      (time_bin == "dh" || time_bin == "h")) {
      data <- data[!(date(data$Time) == date(check[1, 3]) & hour(data[nrow(data), 3]) == hour(check[1, 3])),]
    }
  }, error = function(e) {
    finished <- T
  })
  back <- 10000000 - (nrow(data))
  preprocessed_data <- preprocessing(data)
  features <- feature_extraction(preprocessed_data, optimized_arguments, split <- T)
  return(list(features = features, finished = finished, back = back))
}


# To ignore unnecessary data all user ids<=10.000 will be deleted
# Duplicates will also be deleted
preprocessing <- function(data) {
  data <- data[!(data$User %in% c(0:10000)),] # TODO=Parameter User ids to ignore
  data <- data %>% distinct(Event_ID, User, Host, Time, Source, Source_Port, Logon_Type)
  return(data)
}

################################
# Function to extract features #
################################

feature_extraction <- function(data, parsed_arguments, split = F) {

  view <- parsed_arguments$view
  startdate <- parsed_arguments$startdate
  enddate <- parsed_arguments$enddate
  cores <- parsed_arguments$cores
  time_bin_size <- parsed_arguments$time_bin_size

  functionset <- build_functionset_extraction(parsed_arguments)
  feature_function <- functionset$feature_function
  feature_namens <- functionset$feature_namens
  event_type <- functionset$event_type
  time_window <- functionset$time_window

  # Cluster out of x cores, to speed up
  cluster <- makeCluster(cores)
  registerDoParallel(cluster)

  features <- data.frame()
  # If source view has been choosen delet all NA values
  if (view == 5) {
    data <- data[(is.na(data$Source) != T),]
  }

  cat("Please magnify the window big enough to present the progress bar completly.", fill = 2)

  # Create a progressbar to show progress
  rows <- nrow(data[(data$Time >= (as.Date(startdate)) & (data$Time < (as.Date(enddate)))),])
  progress_bar <- txtProgressBar(min = 0, max = rows, width = 100, style = 3, char = "=", file = stderr(), title = "Feature extraction:")
  processed <- 0
  i <- 0

  # Iterates through the time interval
  repeat {
    # Extract all data in this time window
    window <- data[(data$Time >= (as_datetime(startdate) %m+% time_window(i)) & (data$Time < (as_datetime(startdate) %m+% time_window(i + 1 + time_bin_size)))),]
    # If its empty ignore it
    if (nrow(window) > 0) {
      # Extract per view user/sources/hosts without duplicates
      iter <- distinct(window, window[[view]])
      # Passes through the data for each iter

      # parallelisierung
      results <- foreach(j = 1:length(iter[, 1]), .packages = c("lubridate", "dplyr", "hms", "R.utils"), .combine = rbind) %dopar% {
        # Extract data for this view
        data_identifier <- window[(window[, view] == iter[j, 1]),]
        result <- data.frame()
        # Use the functions for extraction
        for (k in 1:length(feature_function)) {
          result[1, k] <- doCall(feature_function[[k]], args = list(data_identifier = data_identifier, view = view, startdate = startdate, i = i, event_type = event_type[[k]]), .ignoreUnusedArgs = T)
        }
        return(result)
      }

      # Add the results per round
      features <- rbind(features, results)

      # Shows progress
      processed <- processed + nrow(window)
      setTxtProgressBar(progress_bar, processed, title = "Feature extraction:")
      flush.console()
    }

    # Termination condition
    if ((as_datetime(startdate) %m+% time_window(i + 1 + time_bin_size)) >= as_datetime(enddate)) {
      break
    }
    i <- i + 1 + time_bin_size
  }
  # Stops cluster
  stopCluster(cluster)
  close(progress_bar)

  # Add Featurenames
  colnames(features) <- feature_namens

  # If the data is not splited, group it
  if (split != T && parsed_arguments$group == T) {
    features <- group_features(features, view, parsed_arguments$time_bin, cores, load_model = parsed_arguments$load_model, model_path = parsed_arguments$model_path, save_model = parsed_arguments$save_model, path = parsed_arguments$path)
  }

  return(features)
}

# Constructs the feature functions
build_functionset_extraction <- function(parsed_arguments) {

  time_bin <- parsed_arguments$time_bin
  view <- parsed_arguments$view
  days_instead <- parsed_arguments$days_instead

  # Which Feature will be used, needed becuase of modularity
  feature_function <- c()
  feature_namens <- c()

  # ID will always be used
  feature_function <- append(feature_function, Identifier)
  feature_namens <- append(feature_namens, "Identifier")

  # Time Features
  time_bin_functions <- time_bin_functionset_build(time_bin, days_instead, feature_function, feature_namens)
  feature_function <- time_bin_functions$feature_function
  feature_namens <- time_bin_functions$feature_namens
  time_window <- time_bin_functions$time_window

  # Count Features
  feature_function <- append(feature_function, number_events)
  feature_namens <- append(feature_namens, "number_events")

  types <- list(2, 3, 9, 10, c(11, 12))
  start_typ <- length(feature_function) + 1
  for (z in 1:length(types)) {
    feature_function <- append(feature_function, proportion_event)
    feature_namens <- append(feature_namens, paste("Proportion", paste(as.character(unlist(types[[z]])), collapse = "_"), sep = "_"))
  }
  end_typ <- start_typ + length(types) - 1
  feature_function <- append(feature_function, events_per_second)
  feature_namens <- append(feature_namens, "events_per_second")

  # Features per View
  view_functions <- view_functionset_build(view, feature_function, feature_namens)
  feature_function <- view_functions$feature_function
  feature_namens <- view_functions$feature_namens

  # Later its needable to have an iteratble list, thats why logon type list contains unimportant information
  event_type <- rep(list(0), length(feature_function))
  for (z in 1:(end_typ - start_typ + 1) - 1) {
    event_type[[(start_typ + z)]] <- types[[z + 1]]
  }

  return(list(feature_function = feature_function, feature_namens = feature_namens, event_type = event_type, time_window = time_window))
}

# Time Feature
time_bin_functionset_build <- function(time_bin, days_instead, feature_extractors, feature_namens) {

  if (time_bin == "d") {
    if (days_instead) {
      feature_extractors <- append(feature_extractors, day_feature_2)
      feature_namens <- append(feature_namens, "day")
    }else {
      feature_extractors <- append(feature_extractors, weekday)
      feature_namens <- append(feature_namens, "weekday")
    }
    time_window <- days
  }else if (time_bin == "h") {
    feature_extractors <- append(feature_extractors, hour_feature)
    feature_namens <- append(feature_namens, "hour")
    time_window <- hours
  }else {
    feature_extractors <- append(feature_extractors, day_feature)
    feature_extractors <- append(feature_extractors, hour_feature)
    feature_namens <- append(feature_namens, c("day", "hour"))
    time_window <- hours
  }
  return(list(feature_function = feature_extractors, feature_namens = feature_namens, time_window = time_window))
}

# View Feature
view_functionset_build <- function(view, feature_function, feature_namens) {
  if (view == 2) {
    feature_function <- append(feature_function, Users_per_X)
    feature_function <- append(feature_function, Sources_per_X)
    feature_namens <- append(feature_namens, c("Users_per_Host", "Sources_per_Host"))
  }else if (view == 4) {
    feature_function <- append(feature_function, Hosts_per_X)
    feature_function <- append(feature_function, Sources_per_X)
    feature_namens <- append(feature_namens, c("Hosts_per_User", "Sources_per_User"))
  }else {
    feature_function <- append(feature_function, Users_per_X)
    feature_function <- append(feature_function, Hosts_per_X)
    feature_namens <- append(feature_namens, c("Users_per_Source", "Hosts_per_Source"))
  }
  return(list(feature_function = feature_function, feature_namens = feature_namens))
}

#############################
# LIST OF FEATURE FUNCTIONS #
#############################

Identifier <- function(data_identifier, view, ...) {
  return(data_identifier[1, view])
}

weekday <- function(startdate, i, ...) {
  return(wday(ymd(as.Date(startdate) %m+% days(i)), week_start = getOption("lubridate.week.start", 1)))
}

hour_feature <- function(i, ...) {
  return(as_hms(((i) %% 24) * 60 * 60))
}

day_feature <- function(startdate, i, ...) {
  return(as_date((as.Date(startdate) %m+% hours((i)))))
}

day_feature_2 <- function(startdate, i, ...) {
  return(as_date((as.Date(startdate) %m+% days((i)))))
}

number_events <- function(data_identifier, ...) {
  return(nrow(data_identifier))
}


proportion_event <- function(data_identifier, event_type, ...) {
  return(nrow(data_identifier[(data_identifier$Logon_Type %in% event_type),]) / nrow(data_identifier))
}

events_per_second <- function(data_identifier, ...) {
  anzahl <- nrow(data_identifier)
  if (anzahl == 1) {
    return(0)
  }else if (as.numeric(difftime(max(data_identifier[, 3]), min(data_identifier[, 3]), units = "secs")) == 0) {
    return(1)
  }else {
    return(anzahl / as.numeric(difftime(max(data_identifier$Time), min(data_identifier$Time), units = "secs")))
  }
}

Hosts_per_X <- function(data_identifier, view, ...) {
  return((data_identifier %>%
    distinct(Host, X = .[[view]]) %>%
    group_by(X) %>%
    summarise(n()))$`n()`)
}

Sources_per_X <- function(data_identifier, view, ...) {
  return((data_identifier %>%
    distinct(Source, X = .[[view]]) %>%
    group_by(X) %>%
    summarise(n()))$`n()`)
}

Users_per_X <- function(data_identifier, view, ...) {
  return((data_identifier %>%
    distinct(User, X = .[[view]]) %>%
    group_by(X) %>%
    summarise(n()))$`n()`)
}

# ----------------------------------------------------------------------------------------------------------------------------------------------

##############
# Group View #
##############

# Function to group data into clusters by their means
group_features <- function(features, view, time_bin, cores, label = F, load_model, model_path, save_model, path) {
  # Calculate mean values
  iter_means <- calc_means(features, view, cores)
  # Calculate clusters
  features <- clustern(iter_means, features, 13, label, load_model, model_path, save_model, path)

  # Save model
  if (save_model && label == F) {
    min_max <- min_max_calc(features, time_bin)
    saveRDS(min_max, paste(path, "model/min_max.rds", sep = ""))
  }

  # If its not used as label 0-1 normalize it to speed up the ml process
  if (label == F) {
    if (load_model) {
      min_max <- readRDS(paste(model_path, "min_max.rds", sep = ""))
      min_max_new <- min_max_calc(features, time_bin)
      min_max <- as.numeric(unlist(min_max_calc_2(min_max, min_max_new)))
      if (time_bin == "dh") {
        features[, 3:(ncol(features) - 1)] <- normalize_min_max(features[, 3:(ncol(features) - 1)], min_max)
      }else {
        features[, 2:(ncol(features) - 1)] <- normalize_min_max(features[, 2:(ncol(features) - 1)], min_max)
      }
    }else {
      if (time_bin == "dh") {
        features[, 3:(ncol(features) - 1)] <- normalize(features[, 3:(ncol(features) - 1)], method = "range", range = c(0, 1))
      }else {
        features[, 2:(ncol(features) - 1)] <- normalize(features[, 2:(ncol(features) - 1)], method = "range", range = c(0, 1))
      }
    }
  }

  return(features)
}

# Calculate means
calc_means <- function(features, view, cores) {

  # ignore warnings
  options(warn = -1)
  # Ignore Feature like time
  tryCatch(expr = {
    features_without_factors <- select(features, !one_of(c("Identifier", "User", "day", "weekday", "hour")))
  })

  # IDs
  iter <- distinct(features, Identifier)

  # Cluster
  cl <- makeCluster(cores)
  registerDoParallel(cl)

  # Build means per User/Host/Source
  means <- foreach(j = 1:length(iter[, 1]), .packages = c("lubridate", "dplyr"), .combine = rbind) %dopar% {
    data_iter <- features_without_factors[(features$Identifier == iter[j, 1]),]
    result <- data.frame()
    for (j in 1:ncol(features_without_factors)) {
      result[1, j] <- mean(data_iter[, j])
    }
    return(result)
  }
  stopCluster(cl)

  # Name means
  colnames(means) <- colnames(features_without_factors)

  return(list(iter, means))
}

# Cluster
clustern <- function(iter_means, features, number_clusters, label, load_model, model_path, save_model, path) {

  # If a loaded model is used, its also needed to load the old cluster
  if (load_model) {
    km.res <- readRDS(file = paste(model_path, "cluster.rds", sep = ""))
    groups <- data.frame(Groups = as.numeric(cl_predict(km.res, iter_means[[2]], type = "class_id")))
  }else {
    # Seed + cluster data
    set.seed(123)
    km.res <- kmeans(iter_means[[2]], number_clusters, algorithm = "Hartigan-Wong", nstart = 100)

    # Extract cluster numbers as labels/feature
    groups <- data.frame(Groups = km.res[["cluster"]])
  }

  if (save_model) {
    saveRDS(km.res, paste(path, "model/cluster.rds", sep = ""))
  }

  # Feature -> first conditions else as Label
  if (label == F) {
    # Group ID and cluster number
    iter <- data.frame(Identifier = iter_means[[1]], Gruppe = as.factor(groups[, 1]))

    # Join Features and iter to add cluster numbers
    features <- left_join(features, iter, by = "Identifier")
    # Construct unique IDs
    uniq_rownames <- c(make.names(features[, 1], unique = T))
    rownames(features) <- uniq_rownames
    features <- features[, -which(names(features) %in% c("Identifier"))]
    features <- features %>% rename(Identifier = Gruppe)
    return(features)
  }else {
    # Use it as Label
    means_label <- data.frame(iter_means[[2]], Gruppe = as.factor(groups[, 1]))
    return(means_label)
  }

}

# Calculates the max and min
min_max_calc <- function(features, time_bin) {
  date_and_hour <- "dh"
  if (time_bin == date_and_hour) {
    start <- 3
  }else {
    start <- 2
  }
  min_max <- data.frame()
  j <- 1
  for (i in 1:ncol(features[, start:(ncol(features) - 1)]) + start - 1) {
    min_max[j, 1] <- min(features[, i])
    min_max[j, 2] <- max(features[, i])
    j <- j + 1
  }
  return(min_max)
}

# Calcs the new min max if loaded model with existing min maxs are used
min_max_calc_2 <- function(min_max, min_max_new) {
  for (i in 1:ncol(min_max)) {
    min_max[i, 1] <- min(min_max[i, 1], min_max_new[i, 1])
    min_max[i, 2] <- max(min_max[i, 2], min_max_new[i, 2])
  }
  return(min_max)
}

normalize_2 <- function(features, min, max) {

  min_max_normalize <- function(features, min, max) {
    return((features - min) / (max - min))
  }

  return(sapply(features, min_max_normalize, min = min, max = max))
}


normalize_min_max <- function(features, min_max) {
  for (i in 1:ncol(features)) {
    features[, i] <- normalize_2(features[, i], min = min_max[i], max = min_max[ncol(features) + 1])
  }
  return(features)
}

#########################
# Statistical Functions #
#########################

data_statistics <- function(data, path) {
  write_general_infos(data, path)
  logontype(data, path)
  timeline <- timeline_month(data, path)
  borders <- calc_borders(timeline)
  timeline_day(data, path, borders[[1]], borders[[2]])
  user_with_most_logontype_x(data, path)
  return(borders)
}

logontype <- function(data, path) {
  logontype <- data.frame()
  for (i in 1:14 - 1) {
    logontype_x <- data[(data$Logon_Type == i),]
    logontype[i + 1, 1] <- i
    logontype[i + 1, 2] <- length(logontype_x[, 1])
  }
  logontype_plot <- ggplot(data = logontype, aes(x = logontype[, 1], y = logontype[, 2])) +
    geom_bar(stat = "identity") +
    xlab("Logon Type") +
    ylab("Anzahl")

  suppressMessages(ggsave(paste(path, "Login_Typen.png", sep = ""), logontype_plot, width = 10, dpi = 300, limitsize = F))
}


write_general_infos <- function(data, path) {
  infos <- c()
  infos[1] <- paste("Existing Well known Source Ports:", paste(as.character(c(data[(data$Source_Port %in% c(1:1023) & is.na(data$Source_Port) != T), "Source_Port"])), collapse = ", "))
  infos[2] <- paste("Number of Hosts:", nrow(group_by(data, data$Host) %>% summarise(n())))
  infos[3] <- paste("Number of Users:", nrow(group_by(data, data$User) %>% summarise(n())))
  infos[4] <- paste("Number of Source-IPs:", nrow(group_by(data, data$Source) %>% summarise(n())))
  infos[5] <- paste("Smallest date of the data:", min(data$Time))
  infos[6] <- paste("Newest date:", max(data$Time))
  write.table(infos, file = paste(path, "general_infos.txt", sep = ""), row.names = F, col.names = F)
}

timeline_month <- function(data, path = 0) {
  i <- 0
  min_date <- as.Date(paste(year(min(data$Time)), month(min(data$Time)), "01", sep = "-"))
  max_date <- as.Date(paste(year(max(data$Time)), month(max(data$Time)), "01", sep = "-"))
  timeline <- data.frame()
  repeat {
    timeline[i + 1, 1] <- (min_date %m+% months(i))
    timeline[i + 1, 2] <- nrow(data[(data$Time >= (min_date %m+% months(i)) & (data$Time < (min_date %m+% months(i + 1)))),])

    if ((min_date %m+% months(i)) == max_date) {
      break
    }
    i <- i + 1
  }
  colnames(timeline) <- c("Time", "Anzahl")

  if (path != 0) {
    timeplot <- ggplot(timeline, aes(x = Time, y = Anzahl)) +
      geom_area(fill = "#69b3a2", alpha = 0.5) +
      geom_line()

    suppressMessages(ggsave(paste(path, "Volle_Zeitreihe_in_Monaten.png", sep = ""), timeplot, width = 50, dpi = 300, limitsize = F))
  }

  return(timeline)
}

calc_borders <- function(timeline) {
  timeline[, 3] <- scale(timeline[, 2])
  border <- as.numeric(quantile(timeline[, 3], (0.90 + nrow(timeline) * 0.00019)))
  left <- timeline[timeline[, 3] > border,]
  return(list(left[1, 1], as.Date(left[nrow(left), 1]) %m+% months(1)))
}

timeline_day <- function(data, path, startdate, enddate) {
  i <- 0
  timeline <- data.frame()
  repeat {
    timeline[i + 1, 1] <- (as.Date(startdate) %m+% days(i))
    timeline[i + 1, 2] <- nrow(data[(data$Time >= (as.Date(startdate) %m+% days(i)) & (data$Time < (as.Date(startdate) %m+% days(i + 1)))),])

    if ((as.Date(startdate) %m+% days(i)) == as.Date(enddate)) {
      break
    }
    i <- i + 1
  }

  colnames(timeline) <- c("Time", "Anzahl")

  timeplot <- ggplot(timeline, aes(x = Time, y = Anzahl)) +
    geom_area(fill = "#69b3a2", alpha = 0.5) +
    geom_line()

  suppressMessages(ggsave(paste(path, "Quantil_Zeitreihe_Tage.png", sep = ""), timeplot, width = 50, dpi = 300, limitsize = F))
}

user_with_most_logontype_x <- function(data, path) {
  logon_types <- distinct(data, data$Logon_Type)
  logons <- c()
  for (i in logon_types[, 1]) {
    users_with_counts <- data[(data$Logon_Type == i),] %>%
      group_by(User) %>%
      summarise(n())
    users_with_counts <- users_with_counts[order(users_with_counts$`n()`, decreasing = T),]
    sum_logontype <- sum(users_with_counts$`n()`)
    users_with_counts[, 2] <- apply(users_with_counts[, 2], 2, function(x) { x / sum_logontype })
    users_with_counts <- slice(users_with_counts, 1:5)
    logons <- append(logons, paste("Users with the most ", i, " Logon types:", sep = ""))
    for (k in 1:nrow(users_with_counts)) {
      logons <- append(logons, paste("                                     ", users_with_counts[k, 1], users_with_counts[k, 2]))
    }
    logons <- append(logons, "")
  }
  write.table(logons, file = paste(path, "users_with_most_logon_types.txt", sep = ""), row.names = F, col.names = F)
}

#----------------------------------------------------------------------------------------------------------------------------------------------------

# If the script start from console as link file, its needed to extract the path to the original path
location_script <- function(file) {
  # Path to link file
  file_loc <- sub("[^/]*$", "", sub("--file=", "", file[grep("--file=.*", file)]))
  if (substring(file_loc, 1, 1) == ".") {
    path_exec <- system("pwd", intern = T)
    link_path <- paste(path_exec, substring(file_loc, 2), sep = "")
  }else {
    link_path <- substring(file_loc, 2)
  }
  # Relative path from link file to dir
  relativ_path <- Sys.readlink(paste("/", link_path, "FindMaliciousEvents", sep = ""))
  # Calculate absolute path
  absolute_path <- paste(getAbsolutePath.default(sub("FindMaliciousEvents.R$", "", relativ_path), workDirectory = paste("/", link_path, sep = "")), "/", sep = "")
  return(absolute_path)
}

# Function for anomaly detection
anomaly_detection <- function(features, parsed_arguments) {
  ml <- parsed_arguments$ml
  path <- parsed_arguments$path
  cores <- parsed_arguments$cores
  load_model <- parsed_arguments$load_model
  save_model <- parsed_arguments$save_model
  model_path <- parsed_arguments$model_path
  rank <- parsed_arguments$rank
  mean_rank <- parsed_arguments$mean_rank
  absolute_path <- parsed_arguments$absolute_path

  if (ml == "IF" || ml == "kNN" || ml == "DAGMM") {
    setup_python(absolute_path)
    tryCatch(expr = {
      if (ml == "IF") {
        python_isolationforest(absolute_path, path, cores, rank, mean_rank, load_model, save_model, model_path)
      }else if (ml == "kNN") {
        python_kNN(absolute_path, path, cores, rank, mean_rank, load_model, save_model, model_path)
      }else {
        python_dagmm(absolute_path, path, rank, mean_rank, load_model, save_model, model_path)
      }
    }, error = function(e) {
      stop("An errror appeared into python script.", call. = F)
    })
  }else {
    randomforest(features, parsed_arguments$view, parsed_arguments$time_bin, cores, path, load_model, model_path, save_model)
  }
}

# Check if Python 3 is installed, if its installed activate a virtual envirmonent
setup_python <- function(path) {
  tryCatch(expr = {
    use_python(as.character(system("which python3", intern = T)))
  }, error = function(e) {
    stop("Python 3 is not installed.", call. = F)
  })
  use_virtualenv(paste(path, "maliciousevents", sep = ""))
}

# Use python function with the isolationforest
python_isolationforest <- function(Input_path, Output_path, cores, rank, mean_rank, load_model, save_model, model_path) {
  source_python(paste(Input_path, "ml/IsolationForest_Anwendung.py", sep = ""))
  isolationforest_exec(Input_path, Output_path, as.integer(cores), rank, mean_rank, load_model, save_model, model_path)
}

# Use python function with the kNN
python_kNN <- function(Input_path, Output_path, cores, rank, mean_rank, load_model, save_model, model_path) {
  source_python(paste(Input_path, "ml/kNN_Anwendung.py", sep = ""))
  knn_exec(Input_path, Output_path, as.integer(cores), rank, mean_rank, load_model, save_model, model_path)
}

# Use python function with the dagmm
python_dagmm <- function(Input_path, Output_path, rank, mean_rank, load_model, save_model, model_path) {
  source_python(paste(Input_path, "ml/DAGMM_Anwendung.py", sep = ""))
  dagmm_exec(Input_path, Output_path, rank, mean_rank, load_model, save_model, model_path)
}

# Use function with the randomforest, to predict the number of clusters the view is visting
randomforest <- function(features, view, time_bin, cores, path, load_model, model_path, save_model) {
  #Clustert die Daten und gibt die Mittelwertdaten+ die Clusternummer als Label zurück
  means_label <- group_features(features, view, time_bin, cores, label = T, load_model, model_path, save_model, path)

  if (load_model) {
    model <- load_randomforest_model(model_path)
  }else {
    # Grid search hyperparameter
    hyper_grid <- grid_search_randomforest(means_label)
    # Trains the model with the best hyperparameters
    model <- ranger(
      formula = Gruppe ~ .,
      data = means_label,
      num.trees = 500,
      mtry = hyper_grid$mtry[1],
      min.node.size = hyper_grid$node_size[1],
      sample.fraction = hyper_grid$sampe_size[1],
      max.depth = hyper_grid$max_deph[1],
      seed = 123
    )
  }

  if (save_model) {
    saveRDS(model, paste(path, "model/", "model.rds", sep = ""))
  }

  # Predict classes on the full data set
  tryCatch(
    expr = {
      preds <- predict(model, data = features[, c(colnames(means_label[-c(ncol(means_label))]))], type = "response")
    }, error = function(e) {
      stop("The features of the data should be the same like the model features.", call. = F)
    }
  )
  # ID+Group
  Identifier_Gruppe <- data.frame(Identifier = features[, 1], Gruppe = as.factor(preds$predictions))

  # Counts how many groups are visted by the person and sorts it
  result <- Identifier_Gruppe %>%
    distinct(Identifier, Gruppe) %>%
    group_by(Identifier) %>%
    summarise(n())
  result <- as.data.frame(result[order(result$`n()`, decreasing = T),])
  # Write result
  write.csv(result, paste(path, "results.csv", sep = ""), row.names = F)
}

#Function to load a saved model
load_randomforest_model <- function(model_path) {
  model <- readRDS(paste(model_path, "model.rds", sep = ""))
  tryCatch(
    expr = {
      model_type <- attr(model$forest, "class")
      if (model_type != "ranger.forest") {
        stop("Use the correct model on load with the correct machine learning option.", call. = F)
      }
    }, error = function(e) {
      stop("Use the correct model on load with the correct machine learning option.", call. = F)
    }
  )
  if (any((model[["forest"]][["independent.variable.names"]] %in% colnames(means_label)) == F)) {
    cat("Your given model contains a feature that is note included in your extracted feature set.", fill = 1)
  }
  return(model)
}

# Grid search randomforest
grid_search_randomforest <- function(means_label) {
  # Split the means values in train and test data
  train <- means_label[sample(1:nrow(means_label), nrow(means_label) * 0.7),]
  test <- means_label[!(rownames(means_label) %in% rownames(train)),]

  # Create hyperparameter grid
  hyper_grid <- expand.grid(
    mtry = seq(2, ncol(means_label) - 1, by = 1),
    node_size = seq(3, 9, by = 2),
    sampe_size = c(.55, .632, .70, .80),
    max_deph = seq(5, 14, by = 2),
    OOB_RMSE = 0,
    pred_test = 0
  )

  # Iterate truth the net and calculate the accuracy
  for (i in 1:nrow(hyper_grid)) {

    # Train model
    model <- ranger(
      formula = Gruppe ~ .,
      data = train,
      num.trees = 500,
      mtry = hyper_grid$mtry[i],
      min.node.size = hyper_grid$node_size[i],
      sample.fraction = hyper_grid$sampe_size[i],
      max.depth = hyper_grid$max_deph[i],
      seed = 123
    )

    # Add OOB error to grid
    hyper_grid$OOB_RMSE[i] <- sqrt(model$prediction.error)
    preds <- predict(model, data = test, type = "response")
    conf <- confusionMatrix(preds$predictions, test$Gruppe)
    hyper_grid$pred_test[i] <- as.numeric(conf$overall[1])
  }

  # Sort the net by accuracy
  hyper_grid <- hyper_grid[order(hyper_grid$pred_test, decreasing = T),]

  return(hyper_grid)
}

#############
# Visualize #
#############

visualization_results <- function(features, path, not_randomforest, rank, mean_rank) {

  results <- read.csv(paste(path, "results.csv", sep = ""))

  if ("hour" %in% colnames(features)) {
    features["hour"] <- as.numeric(seconds(as_hms(sapply(features["hour"], as.character))))
    results["hour"] <- as.numeric(seconds(as_hms(sapply(results["hour"], as.character))))
  }

  identifier <- data.frame(Identifier = sub("^X", "", sub("\\.[0-9]*$", "", results[, 1])))
  iter <- distinct(identifier, Identifier = Identifier)
  if (not_randomforest == F || rank == T) {
    iter <- iter %>% slice(1:50)
  }

  path <- paste(path, "Radarplots/", sep = "")
  dir.create(path)

  palette <- colorRampPalette(colors = c("#000000", "#FFFFF0"))
  palette_outsider <- colorRampPalette(c("red", "purple"))
  par(mar = c(1, 1, 2, 1))
  par(oma = c(0, 0, 0, 0))
  for (i in 1:nrow(iter)) {
    create_plot(results, features, iter, i, not_randomforest, palette_outsider, palette, path, mean_rank)
  }

}

create_plot <- function(results, features, iter, i, not_randomforest, palette_outsider, palette, path, mean_rank) {
  tryCatch(
    expr = {
      extracted_in_outsider <- extract_in_outsider(not_randomforest, mean_rank, iter[i, 1], results, features)
      outsider <- extracted_in_outsider$outsider
      insider <- extracted_in_outsider$insider
      cols <- extracted_in_outsider$cols

      if (not_randomforest) {
        insider <- subset(insider, !(insider %in% outsider))
      }

      if (not_randomforest == T) {
        not_included <- c("Identifier", "day")
        if (mean_rank) {
          cols <- palette(length(cols))
          plot_data <- select(features[insider,], !one_of(not_included))
        }else {
          cols[1:(length(cols) - length(outsider))] <- palette((length(cols) - length(outsider)))
          cols[(length(cols) - length(outsider) + 1):length(cols)] <- palette_outsider(length(outsider))
          plot_data <- rbind(select(features[insider,], !one_of(not_included)), select(features[outsider,], !one_of(not_included)))
        }
      }else {
        cols <- palette(nrow(insider))
        plot_data <- insider[-c(1)]
      }


      cols_in <- alpha(cols, 0.2)

      jpeg(paste(path, i, "_", iter[i, 1], ".jpg", sep = ""), width = 1900, height = 1900, quality = 100, pointsize = 40, res = 120)
      radarchart(plot_data, maxmin = F, axistype = 1, pcol = cols, pfcol = cols_in, plwd = 1, plty = 2, cglty = 1, cglwd = 0.8, cglcol = "#466D3A", vlcex = 0.8, axislabcol = "#00008B")
      dev.off()
    }, error = function(e) {
      cat(paste("No Radarplots for ", iter[i, 1], " generated, because there is just one Feature per view to be plotted.", sep = ""), fill = 1)
    }
  )
}

extract_in_outsider <- function(not_randomforest, mean_rank, iter, results, features) {
  if (not_randomforest == T) {
    if (mean_rank) {
      outsider <- ""
    }else {
      outsider <- grep(paste("^X", iter, "(\\.[0-9]+$){0,1}", sep = ""), results[, 1], value = T)
    }
    insider <- grep(paste("^X", iter, "(\\.[0-9]+$){0,1}", sep = ""), rownames(features), value = T)
    if (length(insider) > 50) {
      insider <- sample(insider, 50)
    }
    cols <- character(length(insider))
  }else {
    insider <- features[(features$Identifier == iter),]
    outsider <- ""
    if (nrow(insider) > 50) {
      insider <- insider[sample(1:nrow(insider), 50),]
    }
    cols <- character(nrow(insider))
  }
  return(list(outsider = outsider, insider = insider, cols = cols))
}

# Calling main-function with the arguments
main(args)

