#!/usr/bin/Rscript --vanilla
#https://www.r-bloggers.com/2019/11/r-scripts-as-command-line-tools/

# Module:            Bachelor thesis
# Theme:             Detect Malicious Login Events
# Author:            Richard Mey <richard.mey@syss.de>
# Status:            02.07.2021

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

  validate_not_empty_arguments(args)
  splitted_args <- split_arguments(args)
  args <- splitted_args$args
  envr_args <- splitted_args$envr_args

  initalize_global_variables()
  validate_arguments(args)
  validate_envr_arguments(envr_args)
  load_libraries()
  parsed_arguments <- parse_arguments(args, envr_args)
  config_data <- load_machine_learning_config(parsed_arguments)
  features <- extract_features_from_file(parsed_arguments)
  validate_config(config_data, parsed_arguments, features)
  anomaly_detection(features, parsed_arguments, config_data)

  if (parsed_arguments$with_plots) {
    visualization_results(features, parsed_arguments$path, parsed_arguments$group,
                          parsed_arguments$rank, parsed_arguments$mean_rank)
  }

  cat("Done.", fill = 1)
}

validate_not_empty_arguments <- function(args) {
  if (length(args[(grep("^--args$", args))]) == 0) {
    stop_and_help("Dataset to prcoess is missing.", call. = F)
  }
}

split_arguments <- function(args) {
  envr_args <- args[1:grep("^--args$", args)]
  args <- args[(grep("^--args$", args) + 1):length(args)]
  return(list(args = args, envr_args = envr_args))
}

validate_arguments <- function(args) {
  read_and_write_permission <- c(4, 2)
  if (args[1] == "--help") {
    help_output()
    quit()
  }else if (file.exists(args[1]) == F) {
    stop_and_help(paste0("The file ", args[1], " needs to exist."), call. = F)
  }else if (dir.exists(args[2]) == F) {
    stop_and_help(paste0("The directory ", args[2], " needs to exists."), call. = F)
  }else if (file.access(as.character(args[2]), read_and_write_permission) == -1) {
    stop_and_help(paste0("The directory (", args[2], ") sufficient rights (w,r) are not given.."), call. = F)
  }
}

validate_envr_arguments <- function(envr_args) {
  if ("--restore" %in% envr_args) {
    stop_and_help("The option --restore should not be used, it will slow down the process.")
  }
}

initalize_global_variables <- function() {

  assign("time_bin_hour", "h", envir = .GlobalEnv)
  assign("time_bin_day", "d", envir = .GlobalEnv)
  assign("time_bin_day_and_hour", "dh", envir = .GlobalEnv)

  assign("time_sorted_filename", "time_sort.csv", envir = .GlobalEnv)

  assign("view_user", 4, envir = .GlobalEnv)
  assign("view_host", 2, envir = .GlobalEnv)
  assign("view_source_ip", 5, envir = .GlobalEnv)

  assign("read_permission", 4, envir = .GlobalEnv)


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
      "-os       Gives overall statictics to given data",
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
      "-m        Choose one of the given machine learning algorithm for evaluation, default is an kNN",
      "          kNN k-nearest-neigbhour",
      "          IF Isolation forest",
      "          DAGMM Deep Autoencoding Gausian Mixture Model",
      "          RF Randomforest - special to rank is the only option",
      "          The config will be loaded automatic, you can configure it to use different machine learning Hyperparameters",
      "-p        Use this to limit your cores to use. The next argument should be the logical count of cores to use, default is cores-1",
      "-r        The output will be a complet ranked list, default principle is first comes first",
      "          m If you want to get it mean ranked ",
      "-s        Save the trained model",
      "-lm       The next argument should be the path to the directory with the trained model information",
      "-n        Plots will not be generated",
      "-i        Use the option to ignore the users from x to y, these could reflect the well-know users. The default is 0 to 10.000.",
      "          Start of ignore",
      "          End of ignore", fill = 36)
}

stop_and_help <- function(message, call. = F, domain = NULL) {
  stop(message,
       "\n",
       help_output(),
       call. = call.,
       domain = domain
  )
}

#########
# Setup #
#########

# function to load and activate all needed libraries
load_libraries <- function() {

  suppressMessages(library(tools))
  suppressMessages(library(dplyr))
  suppressMessages(library(ggplot2))
  suppressMessages(library(lubridate, quietly = T, mask.ok = F))
  suppressMessages(library(hms))
  suppressMessages(library(doParallel))
  suppressMessages(library(R.utils))
  suppressMessages(library(reticulate))
  suppressMessages(library(fmsb))
  suppressMessages(library(BBmisc))
  suppressMessages(library(ranger))
  suppressMessages(library(caret))
  suppressMessages(library(e1071))
  suppressMessages(library(clue))
  suppressMessages(library(yaml))


  # Options
  options(lubridate.week.start = 1) #weekday starts monday
  options("scipen" = 10) # Not realy needed, shows numbers full printed
  Sys.setenv(TZ = 'UTC') # Set System timezone
  pdf(NULL) # GGplot will generate pdf else
}

# Function to parse Arguments from command line
parse_arguments <- function(args, envr_args) {
  parsed_arguments <- list()
  parsed_arguments$path <- create_output_folder(args)
  parsed_arguments$data_path <- data_path_argument(args)
  parsed_arguments$statistics <- statistics_argument(args)
  parsed_arguments$view <- view_argument(args, view = view_user)
  machine_learning_and_group <- machine_learning_argument(args, machine_learning = "kNN", group = T)
  parsed_arguments$machine_learning <- machine_learning_and_group$machine_learning
  parsed_arguments$group <- machine_learning_and_group$group
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
  ignore_interval_users <- ignore_interval_users_argument(args)
  parsed_arguments$first_user_to_ignore <- ignore_interval_users$first_user_to_ignore
  parsed_arguments$last_user_to_ignore <- ignore_interval_users$last_user_to_ignore
  parsed_arguments$absolute_path <- detect_absolute_path_script(envr_args)
  return(parsed_arguments)
}

# Creates new Folder with _X
create_output_folder <- function(args) {
  path <- paste0(as.character(args[2]), "/FindMaliciousEvents_1/")
  if (dir.exists(path) == F) {
    dir.create(path)
  }else {
    directory <- list.dirs(as.character(args[2]), recursive = F, full.names = F)
    findmaliciousevents_directorys <- grep("FindMaliciousEvents_[0-9]+", directory)
    path <- paste0(as.character(args[2]), "/FindMaliciousEvents_",
                   (max(as.numeric(sub("[^0-9]+", "", directory[findmaliciousevents_directorys]))) + 1), "/")
    dir.create(path)
  }
  return(path)
}

# Return Data path
data_path_argument <- function(args) {
  return(getAbsolutePath.default(as.character(args[1])))
}

# Return statistics argument
statistics_argument <- function(args) {

  statistics <- F

  if (length(grep("^-os$", as.character(args))) != 0) {
    statistics <- T
  }
  return(statistics)
}

# Return vview argument
view_argument <- function(args, view) {

  if (length(grep("^-v$", as.character(args))) != 0) {
    if (is.na(args[grep("^-v$", as.character(args)) + 1])) {
      stop_and_help("You did not specify any of the views (u,h,s).", call. = F)
    }else {
      if (as.character(args[grep("^-v$", as.character(args)) + 1]) == "u" ||
        as.character(args[grep("^-v$", as.character(args)) + 1]) == time_bin_hour ||
        as.character(args[grep("^-v$", as.character(args)) + 1]) == "s") {
        if (as.character(args[grep("^-v$", as.character(args)) + 1]) == "u") {
          view <- view_user
        }else if (as.character(args[grep("^-v$", as.character(args)) + 1]) == time_bin_hour) {
          view <- view_host
        }else {
          view <- view_source_ip
        }
      }else {
        stop_and_help("You did not specify any of the validate views (u,h,s).", call. = F)
      }
    }
  }
  return(view)
}

# Return machine_learning arguments
machine_learning_argument <- function(args, machine_learning, group) {

  if (length(grep("^-m$", as.character(args))) != 0) {
    if (is.na(args[grep("^-m$", as.character(args)) + 1])) {
      stop_and_help("You did not specify any of the machine learning options (IF,kNN,DAGMM,RF).", call. = F)
    }else {
      if (as.character(args[grep("^-m$", as.character(args)) + 1]) == "IF" ||
        as.character(args[grep("^-m$", as.character(args)) + 1]) == "kNN" ||
        as.character(args[grep("^-m$", as.character(args)) + 1]) == "DAGMM" ||
        as.character(args[grep("^-m$", as.character(args)) + 1]) == "RF") {
        if (as.character(args[grep("^-m$", as.character(args)) + 1]) == "IF") {
          machine_learning <- "IF"
        }else if (as.character(args[grep("^-m$", as.character(args)) + 1]) == "kNN") {
          machine_learning <- "kNN"
        }else if (as.character(args[grep("^-m$", as.character(args)) + 1]) == "DAGMM") {
          machine_learning <- "DAGMM"
        }else {
          machine_learning <- "RF"
          group <- F
        }
      }else {
        stop_and_help("You did not specify any of valid machine learning options (IF,kNN,DAGMM,RF).", call. = F)
      }
    }
  }
  return(list(machine_learning = machine_learning, group = group))
}


# Return time bin arguments
time_bin_argument <- function(args) {

  time_bin <- time_bin_day
  time_bin_size <- 0
  days_instead <- F

  if (length(grep("^-t$", as.character(args))) != 0) {
    if (is.na(args[grep("^-t$", as.character(args)) + 1])) {
      stop_and_help("You did not specify any of time slot options (d,h,dh).", call. = F)
    }else {
      if (as.character(args[grep("^-t$", as.character(args)) + 1]) == time_bin_hour ||
        as.character(args[grep("^-t$", as.character(args)) + 1]) == time_bin_day ||
        as.character(args[grep("^-t$", as.character(args)) + 1]) == time_bin_day_and_hour) {
        if (as.character(args[grep("^-t$", as.character(args)) + 1]) == time_bin_day) {
          time_bin <- time_bin_day
          if (is.na(args[grep("^-t$", as.character(args)) + 2]) == F &&
            length(grep("-", args[grep("^-t$", as.character(args)) + 2])) == F) {
            if (as.character(args[grep("^-t$", as.character(args)) + 2]) == time_bin_day) {
              days_instead <- T
            }else {
              stop_and_help("The only option you can use here is d.", call. = F)
            }
          }
        }else {
          if (as.character(args[grep("^-t$", as.character(args)) + 1]) == time_bin_hour) {
            time_bin <- time_bin_hour
          }else {
            time_bin <- time_bin_day_and_hour
          }

          if (is.na(args[grep("^-t$", as.character(args)) + 2]) == F &&
            length(grep("-", args[grep("^-t$", as.character(args)) + 2])) == F) {
            if (length(grep("^[0-9]*$", as.character(args[grep("^-t$", as.character(args)) + 2]))) != 0) {
              time_bin_size <- as.numeric(args[grep("^-t$", as.character(args)) + 2]) - 1
              if (time_bin_size < 0 || time_bin_size > 71) {
                stop_and_help("The number of hours need to be, bigger then 0 and smaller then 73.", call. = F)
              }
            }else {
              stop_and_help("Missing a number behind the hour/day-hour time bin format.", call. = F)
            }
          }else {
          }
        }
      }else {
        stop_and_help("You did not specify any of the valid time slot options (d,h,dh).", call. = F)
      }
    }
  }
  return(list(time_bin = time_bin, time_bin_size = time_bin_size, days_instead = days_instead))
}

# Return rank arguments
rank_argument <- function(args) {
  rank <- F
  mean_rank <- F
  if (length(grep("^-r$", as.character(args))) != 0) {
    if (is.na(args[grep("^-r$", as.character(args)) + 1]) != T &&
      length(grep("-", args[grep("^-r$", as.character(args)) + 1])) == F) {
      if (as.character(args[grep("^-r$", as.character(args)) + 1]) == "m") {
        mean_rank <- T
      }else {
        stop_and_help("You did not specify any of the valid rank ptions (m).", call. = F)
      }
    }
    rank <- T
  }
  return(list(rank = rank, mean_rank = mean_rank))
}

# Return time window argument
time_window_argument <- function(args) {
  completely <- F
  if (length(grep("^-d$", as.character(args))) != 0) {
    if (is.na(args[grep("^-d$", as.character(args)) + 1])) {
      stop_and_help("You did not specify an option for start- and enddate (m,v).", call. = F)
    }else {
      if (as.character(args[grep("^-d$", as.character(args)) + 1]) == "m" ||
        as.character(args[grep("^-d$", as.character(args)) + 1]) == "v") {
        if (as.character(args[grep("^-d$", as.character(args)) + 1]) == "m") {
          if (is.na(args[grep("^-d$", as.character(args)) + 2]) && is.na(args[grep("^-d$", as.character(args)) + 3])) {
            stop_and_help("Missing start- and enddate.", call. = F)
          }else {
            tryCatch(expr = {
              startdate <- as_date(args[grep("^-d$", as.character(args)) + 2])
              enddate <- as_date(args[grep("^-d$", as.character(args)) + 3])
            }, warning = function(w) {
              stop_and_help("Missing a valid start- and enddate.", call. = F)
            })
            if (startdate > enddate) {
              stop_and_help("Your startdate is older then the enddate, change the information.", call. = F)
            }
          }
        }else {
          completely <- T
        }
      }else {
        stop_and_help("You did not specify a valid option for the start- and enddate (m,v).", call. = F)
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
  if (length(grep("^-p$", as.character(args))) != 0) {
    if (is.na(args[grep("^-p$", as.character(args)) + 1])) {
      stop_and_help("Missing a number of logical processors to use.", call. = F)
    }else {
      tryCatch(expr = {
        cores <- as.numeric(args[grep("^-p$", as.character(args)) + 1])
        if (cores > detectCores()) {
          stop_and_help("You can´t use a bigger number of logicals processors then available.", call. = F)
        }else if (cores < 1) {
          stop_and_help("You can´t use a smaller number of logicals processors then one.", call. = F)
        }
      }, warning = function(w) {
        stop_and_help("You did not specify a number of cores, based on your processor.", call. = F)
      })
    }
  }else {
    cores <- detectCores() - 1
  }
  return(cores)
}

# Return load model arguemnts
load_model_argument <- function(args) {
  if (length(grep("^-lm$", as.character(args))) != 0) {
    if (is.na(args[grep("^-lm$", as.character(args)) + 1])) {
      stop_and_help("Missing a path to the directory with the model information.", call. = F)
    }else {
      model_path <- as.character(args[grep("^-lm$", as.character(args)) + 1])
      if (dir.exists(model_path) == F) {
        stop_and_help("You did not specify an existing model directory.", call. = F)
      }
      if (file.exists(paste0(model_path, "cluster.rds")) == F ||
        (file.exists(paste0(model_path, "min_max.rds")) == F && machine_learning != "RF") ||
        (file.exists(paste0(model_path, "model.joblib")) == F &&
          file.exists(paste0(model_path, "model.rds")) == F &&
          file.exists(paste0(model_path, "model.index")) == F)) {
        stop_and_help("Missing a directory that contains the following content: (min_max.rds), cluster.rds, model.(rds/joblib/index). ")
      }

      if ((file.exists(paste0(model_path, "model.rds")) == F && machine_learning == "RF") ||
        (file.exists(paste0(model_path, "model.rds")) == T && (machine_learning == "IF" || machine_learning == "kNN")) ||
        (file.exists(paste0(model_path, "model.index")) == F && machine_learning == "DAGMM")) {
        stop_and_help("The loaded model is not compatible with the machine learning option.", call. = F)
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
  if (length(grep("^-s$", as.character(args))) != 0) {
    save_model <- T
    dir.create(paste0(path, "model/"))
  }else {
    save_model <- F
  }
  return(save_model)
}

# With out plots argument
with_plots_argument <- function(args) {
  if (length(grep("^-n$", as.character(args))) != 0) {
    with_plots <- F
  }else {
    with_plots <- T
  }
  return(with_plots)
}

# Extracted Feature Argument
extracted_features_argument <- function(args) {
  if (length(grep("^-e$", as.character(args))) != 0) {
    extracted_features <- T
  }else {
    extracted_features <- F
  }
  return(extracted_features)
}

ignore_interval_users_argument <- function(args) {

  first_user_to_ignore <- 0
  last_user_to_ignore <- 10000

  if (length(grep("^-i$", as.character(args))) != 0) {
    if (is.na(args[grep("^-i$", as.character(args)) + 1]) || is.na(args[grep("^-i$", as.character(args)) + 2])) {
      stop_and_help("You did not specify an interval for first- and last users to ignore.", call. = F)
    }else {
      if (length(grep("[-0-9]*", args[grep("^-i$", as.character(args)) + 1])) == 0 ||
        length(grep("[-0-9]*", args[grep("^-i$", as.character(args)) + 2])) == 0) {
        stop_and_help("You did not specify a numeric interval for first- and last users to ignore.", call. = F)
      }else {
        tryCatch(
          expr = {
            first_user_to_ignore <- as.integer(args[grep("^-i$", as.character(args)) + 1])
            last_user_to_ignore <- as.integer(args[grep("^-i$", as.character(args)) + 2])
          }, warning = function(w) {
            stop_and_help(paste("One of the inserted numbers", args[grep("^-i$", as.character(args)) + 1], ",",
                                args[grep("^-i$", as.character(args)) + 2], "for the first and last user to ignore, is not numeric."))
          }
        )
      }
    }
  }
  return(list(first_user_to_ignore = first_user_to_ignore, last_user_to_ignore = last_user_to_ignore))
}

# Main Function to generate or read Features
extract_features_from_file <- function(parsed_arguments) {
  if (parsed_arguments$extracted_features) {
    features <- read_in_features_from_file(parsed_arguments$data_path)
  }else {
    data <- read_in_data(parsed_arguments$data_path, parsed_arguments$path)
    if (is.null(nrow(data)) == F) {
      features <- extract_features(data, parsed_arguments)
    }else {
      if (is.null(parsed_arguments$startdate) == T && parsed_arguments$completely == F) {
        stop_and_help("Missing a start- and enddate, if the file is to large to be splitted.", call. = F)
      }
      # TODO=loop{edges,extract features)
      features <- feature_extraction_parted_from_file(parsed_arguments)
    }
  }
  return(features)
}

# If the option -e has been choosen, Features which has been created with this program can be loaded
read_in_features_from_file <- function(data_path) {
  if (file_ext(data_path) == "csv") {
    if (file.access(data_path, read_permission) == -1) {
      stop_and_help("Missing a file for which you got the rights to read.", call. = F)
    }
    tryCatch(expr = {
      features <- read.csv(data_path, row.names = 1)
      possible_features <- "weekday|number_events|proportion_[0-9_]+|hour|day|events_per_second|Identifier|Users_per_Host|Users_per_Source|Hosts_per_User|Hosts_per_Source|Sources_per_User|Sources_per_Host"
      if (length(grep(possible_features, colnames(features), invert = T)) != 0) {
        stop_and_help("The inserted Feature set, does not match the feature the programs generate.", call. = F)
      }
      return(features)
    }, error = function(e) {
      stop_and_help("The file is not empty or valid.", call. = F)
    }, warning = function(w) {
    })

  }else {
    stop_and_help("The specified file needs to match with one of the acceptable file formats (csv).", call. = F)
  }
}

# Read raw data
read_in_data <- function(data_path, path) {
  # R loads all data in the memory, so if the raw data it cant read all without crashing, thats why it can be splited read in
  # Read in free memory
  memory <- get_free_memory()

  # Read in data file size
  file_size <- as.numeric(file.info(data_path)$size) / 1000000

  # End program if its not csv
  if (file_ext(data_path) == "csv") {
    # If the user dont got enough rights, end
    if (file.access(data_path, read_permission) == -1) {
      stop_and_help("Missing a file for which you got the rights to read.", call. = F)
    }

    # If the raw data file, occupied more than 40% of the memory -> parted read in
    if (file_size >= memory * 0.4) {
      cat("The specified file is too large, hence the read-in/ preprocessing/ feature extraction will be splited. This process might take more time.",
          fill = 2)
      split <- T
      # To let the features be complety, sort it by time
      system(paste0("sort -k3 -t, ", data_path, " >> ", path, time_sorted_filename))
      return(split)
    }else {
      # <40% read data
      tryCatch(expr = {
        data <- read.csv(data_path, colClasses = c("integer", "numeric", "POSIXct", "numeric", "numeric", "numeric", "integer", "integer"), header = F)
      }, error = function(e) {
        stop_and_help("Missing a valid, non-empty file and in accordance with the format: Int,Num,Date,Num,Num,Num,Int,Int.", call. = F)
      }, warning = function(w) {
        stop_and_help("The file needs the following columns: Event_ID,Host,Time,Logon_ID,User,Source,Source Port,Logon Typ.", call. = F)
      })

      # If the data is smaller than 1000 rows, the program will stop_and_help working, because its too less
      if (nrow(data) < 1000) {
        stop_and_help("The file contains fewer then 1000 rows. You should use one with more.", call. = F)
      }

      # Rename columns and delet all Events that dont fit to 4624
      colnames(data) <- c("Event_ID", "Host", "Time", "Logon_ID", "User", "Source", "Source_Port", "Logon_Type") #ActivityID oder LogonGUID
      data <- data[(data$Event_ID == 4624),]
      return(data)
    }

  }else {
    stop_and_help("The specified file needs to match with one of the acceptable file formats (csv).", call. = F)
  }

}

# Get the free memory
get_free_memory <- function() {
  memory <- system('free -m', intern = T)
  memory <- strsplit(memory, " ")
  memory <- as.numeric(tail(memory[[2]], n = 1))
  return(memory)
}

# If the file size is to large, read it in parts
parted_read_in_data <- function(path, row_multi, back) {
  tryCatch(expr = {
    # read in x rows and skip all before
    data_new <- read.csv(paste0(path, time_sorted_filename), nrows = 10000000, skip = (row_multi * 10000000) - back,
                         colClasses = c("integer", "numeric", "POSIXct", "numeric", "numeric", "numeric", "integer", "integer"),
                         header = F)
    colnames(data_new) <- c("Event_ID", "Host", "Time", "Logon_ID", "User", "Source", "Source_Port", "Logon_Type") #ActivityID oder LogonGUID
    data_new <- data_new[(data_new$Event_ID == 4624),]
    return(data_new)
  }, error = function(e) {
    if (row_multi == 0) {
      stop_and_help("Missing a valid, non-empty file and in accordance with the format: Int,Num,Date,Num,Num,Num,Int,Int.")
    }else {
      finished <- T
      return(finished)
    }
  }, warning = function(w) {
    stop_and_help("The file needs the following columns: Event_ID,Host,Time,Logon_ID,User,Source,Source Port,Logon Typ.")
  })
}

# Feature extraction without splitting data before
extract_features <- function(data, parsed_arguments) {

  start_and_enddate <- set_start_and_enddate(data, parsed_arguments)
  parsed_arguments$startdate <- start_and_enddate$startdate
  parsed_arguments$enddate <- start_and_enddate$enddate

  # If statistics is true do pre and post statistics
  if (parsed_arguments$statistics) {
    data_statistics(data, parsed_arguments, "pre")
  }

  # Do preprocessing
  data <- preprocessing(data, parsed_arguments)

  if (parsed_arguments$statistics) {
    data_statistics(data, parsed_arguments, "post")
  }

  if (nrow(data[(data$Time >= (as.Date(parsed_arguments$startdate)) &
    (data$Time < (as.Date(parsed_arguments$enddate)))),]) == 0) {
    stop_and_help("Missing a start- and enddate, that fits to the data.", call. = F)
  }

  features <- feature_extraction(data, parsed_arguments)
  write.csv(features, paste0(parsed_arguments$path, "Features.csv"))

  return(features)
}

# Control the start- and enddate, if no dates are given calculate some
set_start_and_enddate <- function(data, parsed_arguments) {
  if (is.null(parsed_arguments$startdate)) {
    if (parsed_arguments$completely) {
      startdate <- as_date(min(data$Time))
      enddate <- as_date(max(data$Time))
    }else {
      calculated_start_and_enddate <- calculate_start_and_enddate(generate_timeline_month(data))
      startdate <- calculated_start_and_enddate[[1]]
      enddate <- calculated_start_and_enddate[[2]]
    }
  }else {
    startdate <- parsed_arguments$startdate
    enddate <- parsed_arguments$enddate
  }
  return(list(startdate = startdate, enddate = enddate))
}

# Feature extraction in parts
feature_extraction_parted_from_file <- function(parsed_arguments) {

  finished <- F
  row_multi <- 0
  back <- 0
  features <- data.frame()

  # Read-in data until its 
  while (finished == F) {
    data <- parted_read_in_data(parsed_arguments$path, row_multi, back)

    if (is.null(nrow(data)) == F) {

      optimized_date <- optimize_date(data, parsed_arguments)
      finished <- optimized_date$finished

      # If data contains date interval, that doesnt fit to start and enddate, ignore it
      if (optimized_date$ignore_period == F) {
        parted_feature_result <- parted_feature_extraction(data, finished, optimized_date$optimized_arguments,
                                                           back, row_multi)
        finished <- parted_feature_result$finished
        back <- parted_feature_result$back
        features <- rbind(features, parted_feature_result$features)
      }
      rm(data)
    }else {
      finished <- T
    }
    row_multi <- row_multi + 1
  }

  validate_not_empty_features(features)

  if (parsed_arguments$group == T) {
    grouped_features <- group_features(features, parsed_arguments$time_bin, parsed_arguments$cores,
                                       load_model = parsed_arguments$load_model,
                                       model_path = parsed_arguments$model_path,
                                       save_model = parsed_arguments$save_model, path = parsed_arguments$path)
  }
  write.csv(grouped_features, paste0(parsed_arguments$path, "Features.csv"))

  return(grouped_features)
}

validate_not_empty_features <- function(features) {
  if (is.null(features[1, 1])) {
    stop_and_help("Missing a start- and enddate, that fits to the data.", call. = F)
  }
}

# Optimize date on parted Feature extraction
optimize_date <- function(data, parsed_arguments) {

  finished <- F
  ignore_period <- F
  optimized_arguments <- parsed_arguments

  if (parsed_arguments$completely != T) {

    enddate_optimized <- parsed_arguments$enddate
    startdate_optimized <- parsed_arguments$startdate

    if (startdate_optimized > as_date(max(data$Time))) {
      ignore_period <- T
    }else if (enddate_optimized < as_date(min(data$Time))) {
      finished <- T
      ignore_period <- T
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

  optimized_arguments$startdate <- startdate_optimized
  optimized_arguments$enddate <- enddate_optimized

  return(list(optimized_arguments = optimized_arguments, ignore_period = ignore_period, finished = finished))
}

# Function to check how many steps to go back and to do feature extraction 
parted_feature_extraction <- function(data, optimized_arguments, back, row_multi) {
  edgeless_data_finished_flag <- delete_edges(data, optimized_arguments, back, row_multi)
  edgeless_data <- edgeless_data_finished_flag$edgeless_data
  new_back <- (10000000 - (nrow(edgeless_data))) + back # TODO=global oder Argument
  preprocessed_data <- preprocessing(edgeless_data, optimized_arguments)
  features <- feature_extraction(preprocessed_data, optimized_arguments, split = T)
  return(list(features = features, finished = edgeless_data_finished_flag$finished, back = new_back))
}

delete_edges <- function(data, optimized_arguments, back, row_multi) {

  time_bin <- optimized_arguments$time_bin
  time_bin_size <- optimized_arguments$time_bin_size

  tryCatch(expr = {
    next_row_of_data <- read.csv(paste0(optimized_arguments$path, time_sorted_filename), nrows = 1,
                                 skip = ((row_multi + 1) * 10000000) - back + 1,
                                 colClasses = c("integer", "numeric", "POSIXct", "numeric", "numeric", "numeric", "integer", "integer"),
                                 header = F, col.names = c("Event_ID", "Host", "Time", "Logon_ID", "User", "Source", "Source_Port", "Logon_Type"))
    if (date(data[nrow(data), 3]) == date(next_row_of_data[1, 3]) && time_bin == time_bin_day) {
      edgeless_data <- data[!(date(data$Time) == date(check[1, 3])),]
      # }else if(((as_datetime(data[nrow(data),3])-hours(time_bin_size+1))>=as_datetime(check[1,3])) && hour(data[nrow(data),3])==hour(check[1,3]) && (time_bin==time_bin_day_and_hour || time_bin==time_bin_hour) && optimized_arguments$time_bin_size>0){
      #  edgeless_data<-data[!(as_datetime(data$Time>=))]
    }else if (date(data[nrow(data), 3]) == date(next_row_of_data[1, 3]) &&
      hour(data[nrow(data), 3]) == hour(next_row_of_data[1, 3]) &&
      (time_bin == time_bin_day_and_hour || time_bin == time_bin_hour)) {
      edgeless_data <- data[!(date(data$Time) == date(check[1, 3]) & hour(data[nrow(data), 3]) == hour(check[1, 3])),]
    }
  }, error = function(e) {
    return(list(edgeless_data = data, finished = T))
  })
  return(list(edgeless_data = edgeless_data, finished = F))
}


# To ignore unnecessary data all user ids from first_user_to_ignore to last_user_to_ignore will be deleted
# Duplicates will also be deleted
preprocessing <- function(data, parsed_arguments) {
  deleted_users_data <- data[!(data$User %in%
    parsed_arguments$first_user_to_ignore:parsed_arguments$last_user_to_ignore),]
  without_duplicates_data <- deleted_users_data %>%
    distinct(Event_ID, User, Host, Time, Source, Source_Port, Logon_Type)
  return(without_duplicates_data)
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
  feature_extractors <- functionset$feature_extractors
  event_type <- functionset$event_type
  time_window <- functionset$time_window

  # Cluster out of x cores, to speed up
  cluster_of_cores <- makeCluster(cores)
  registerDoParallel(cluster_of_cores)

  features <- data.frame()
  # If source view has been choosen delet all NA values
  if (view == 5) { # TODO=Warum oder globale Variable anstatt 5
    data <- data[(is.na(data$Source) != T),]
  }

  cat("Please magnify the window big enough to present the progress bar completly.", fill = 2)

  progress_bar <- create_progress_bar(data, startdate, enddate)
  processed <- 0
  i <- 0

  # Iterates through the time interval
  repeat {
    # Extract all data in this time window
    window <- data[(data$Time >= (as_datetime(startdate) %m+% time_window(i)) &
      (data$Time < (as_datetime(startdate) %m+% time_window(i + 1 + time_bin_size)))),]
    if (nrow(window) > 0) {
      # Extract per view user/sources/hosts without duplicates
      iterator <- distinct(window, window[[view]])
      # parallelisierung
      results <- foreach(j = seq_along(iterator[, 1]), .packages = c("lubridate", "dplyr", "hms", "R.utils"),
                         .combine = rbind) %dopar% {
        # Extract data for this view
        data_identifier <- window[(window[, view] == iterator[j, 1]),]
        result <- data.frame()
        # Use the functions for extraction
        for (k in seq_along(feature_extractors)) {
          result[1, k] <- doCall(feature_extractors[[k]], args = list(data_identifier = data_identifier,
                                                                      view = view, startdate = startdate, i = i,
                                                                      event_type = event_type[[k]],
                                                                      time_window = time_window), .ignoreUnusedArgs = T)
        }
        return(result)
      }

      features <- rbind(features, results)

      processed <- processed + nrow(window)
      setTxtProgressBar(progress_bar, processed, title = "Feature extraction:")
    }

    if ((as_datetime(startdate) %m+% time_window(i + 1 + time_bin_size)) >= as_datetime(enddate)) {
      break
    }
    i <- i + 1 + time_bin_size
  }
  stopCluster(cluster_of_cores)
  close(progress_bar)

  colnames(features) <- functionset$feature_namens

  # If its splitted it needs to be done later on the complet feature set
  if (split != T && parsed_arguments$group == T) {
    features <- group_features(features, parsed_arguments$time_bin, cores, load_model = parsed_arguments$load_model,
                               model_path = parsed_arguments$model_path, save_model = parsed_arguments$save_model,
                               path = parsed_arguments$path)
  }

  return(features)
}

create_progress_bar <- function(data, startdate, enddate) {
  processing_data <- nrow(data[(data$Time >= (as.Date(startdate)) & (data$Time < (as.Date(enddate)))),])
  progress_bar <- txtProgressBar(min = 0, max = processing_data, width = 100, style = 3, char = "=", file = stderr(),
                                 title = "Feature extraction:")
  return(progress_bar)
}

build_functionset_extraction <- function(parsed_arguments) {

  # Which Feature will be used, needed becuase of modularity
  feature_extractors <- NULL
  feature_namens <- NULL

  # ID will always be used
  feature_extractors <- append(feature_extractors, Identifier_extractor)
  feature_namens <- append(feature_namens, "Identifier")

  # Time Features
  time_bin_functions <- time_bin_functionset_build(parsed_arguments$time_bin, parsed_arguments$days_instead,
                                                   feature_extractors, feature_namens)
  feature_extractors <- time_bin_functions$feature_extractors
  feature_namens <- time_bin_functions$feature_namens
  time_window <- time_bin_functions$time_window

  # Count Features
  feature_extractors <- append(feature_extractors, number_events_extractor)
  feature_namens <- append(feature_namens, "number_events")

  types <- list(2, 3, 9, 10, c(11, 12))
  start_typ <- length(feature_extractors) + 1
  for (z in seq_along(types)) {
    feature_extractors <- append(feature_extractors, proportion_event_extractor)
    feature_namens <- append(feature_namens, paste("proportion",
                                                   paste(as.character(unlist(types[[z]])), collapse = "_"), sep = "_"))
  }
  end_typ <- start_typ + length(types) - 1
  feature_extractors <- append(feature_extractors, events_per_second_extractor)
  feature_namens <- append(feature_namens, "events_per_second")

  # Features per View
  view_functions <- view_functionset_build(parsed_arguments$view, feature_extractors, feature_namens)
  feature_extractors <- view_functions$feature_extractors
  feature_namens <- view_functions$feature_namens

  # Later its needable to have an iteratble list, thats why logon type list contains unimportant information
  event_type <- rep(list(0), length(feature_extractors))
  for (z in 1:(end_typ - start_typ + 1) - 1) {
    event_type[[(start_typ + z)]] <- types[[z + 1]]
  }

  return(list(feature_extractors = feature_extractors, feature_namens = feature_namens,
              event_type = event_type, time_window = time_window))
}

# Time Feature
time_bin_functionset_build <- function(time_bin, days_instead, feature_extractors, feature_namens) {

  switch(time_bin,
         "d" = {
           if (days_instead) {
             feature_extractors <- append(feature_extractors, day_feature_2)
             feature_namens <- append(feature_namens, "day")
           }else {
             feature_extractors <- append(feature_extractors, weekday_extractor)
             feature_namens <- append(feature_namens, "weekday")
           }
           time_window <- days
         },
         "h" = {
           feature_extractors <- append(feature_extractors, hour_extractor)
           feature_namens <- append(feature_namens, "hour")
           time_window <- hours
         },
         "dh" = {
           feature_extractors <- append(feature_extractors, day_extractor)
           feature_extractors <- append(feature_extractors, hour_extractor)
           feature_namens <- append(feature_namens, c("day", "hour"))
           time_window <- hours
         }
  )
  return(list(feature_extractors = feature_extractors, feature_namens = feature_namens, time_window = time_window))
}

# View Feature
view_functionset_build <- function(view, feature_extractors, feature_namens) {
  switch(as.character(view),
         "2" = {
           feature_extractors <- append(feature_extractors, Users_per_X_extractor)
           feature_extractors <- append(feature_extractors, Sources_per_X_extractor)
           feature_namens <- append(feature_namens, c("Users_per_Host", "Sources_per_Host"))
         },
         "4" = {
           feature_extractors <- append(feature_extractors, Hosts_per_X_extractor)
           feature_extractors <- append(feature_extractors, Sources_per_X_extractor)
           feature_namens <- append(feature_namens, c("Hosts_per_User", "Sources_per_User"))
         },
         "5" = {
           feature_extractors <- append(feature_extractors, Users_per_X_extractor)
           feature_extractors <- append(feature_extractors, Hosts_per_X_extractor)
           feature_namens <- append(feature_namens, c("Users_per_Source", "Hosts_per_Source"))
         }
  )
  return(list(feature_extractors = feature_extractors, feature_namens = feature_namens))
}

#############################
# LIST OF FEATURE FUNCTIONS #
#############################

Identifier_extractor <- function(data_identifier, view, ...) {
  return(data_identifier[1, view])
}

weekday_extractor <- function(startdate, i, ...) {
  return(wday(ymd(as.Date(startdate) %m+% days(i)), week_start = getOption("lubridate.week.start", 1)))
}

hour_extractor <- function(i, ...) {
  return(as_hms(((i) %% 24) * 60 * 60))
}

day_extractor <- function(startdate, i, time_window, ...) {
  return(as_date((as.Date(startdate) %m+% time_window((i)))))
}

number_events_extractor <- function(data_identifier, ...) {
  return(nrow(data_identifier))
}


proportion_event_extractor <- function(data_identifier, event_type, ...) {
  return(nrow(data_identifier[(data_identifier$Logon_Type %in% event_type),]) / nrow(data_identifier))
}

events_per_second_extractor <- function(data_identifier, ...) {
  number_of_rows <- nrow(data_identifier)
  if (number_of_rows == 1) {
    return(0)
  }else if (as.numeric(difftime(max(data_identifier[, 3]), min(data_identifier[, 3]), units = "secs")) == 0) {
    return(1)
  }else {
    return(number_of_rows / as.numeric(difftime(max(data_identifier$Time),
                                                min(data_identifier$Time), units = "secs")))
  }
}

Hosts_per_X_extractor <- function(data_identifier, view, ...) {
  return((data_identifier %>%
    distinct(Host, X = .[[view]]) %>%
    group_by(X) %>%
    summarise(n()))$`n()`)
}

Sources_per_X_extractor <- function(data_identifier, view, ...) {
  return((data_identifier %>%
    distinct(Source, X = .[[view]]) %>%
    group_by(X) %>%
    summarise(n()))$`n()`)
}

Users_per_X_extractor <- function(data_identifier, view, ...) {
  return((data_identifier %>%
    distinct(User, X = .[[view]]) %>%
    group_by(X) %>%
    summarise(n()))$`n()`)
}

# ----------------------------------------------------------------------------------------------------------------------

##############
# Group View #
##############

# Function to group data into clusters by their means
group_features <- function(features, time_bin, cores, label = F, load_model, model_path, save_model, path) {
  # Calculate mean values
  iter_means <- calculate_means(features, cores)
  # Calculate clusters
  number_clusters <- 13
  cluserted_features <- calculate_cluster(iter_means, features, number_clusters, label,
                                          load_model, model_path, save_model, path)

  # Save model
  if (save_model && label == F) {
    min_max <- calculate_min_max(cluserted_features, time_bin)
    saveRDS(min_max, paste0(path, "model/min_max.rds"))
  }

  # If its not used as label 0-1 normalize it to speed up the machine_learning process
  if (label == F) {
    if (load_model) {
      min_max <- readRDS(paste0(model_path, "min_max.rds"))
      min_max_new <- calculate_min_max(cluserted_features, time_bin)
      min_max <- as.numeric(unlist(calculate_from_two_min_max(min_max, min_max_new)))
      if (time_bin == time_bin_day_and_hour) {
        cluserted_features[, 3:(ncol(features) - 1)] <- complet_normalize_features(
          cluserted_features[, 3:(ncol(features) - 1)], min_max)
      }else {
        cluserted_features[, 2:(ncol(features) - 1)] <- complet_normalize_features(
          cluserted_features[, 2:(ncol(features) - 1)], min_max)
      }
    }else {
      if (time_bin == time_bin_day_and_hour) {
        cluserted_features[, 3:(ncol(features) - 1)] <- normalize(
          cluserted_features[, 3:(ncol(features) - 1)], method = "range", range = c(0, 1))
      }else {
        cluserted_features[, 2:(ncol(features) - 1)] <- normalize(
          cluserted_features[, 2:(ncol(features) - 1)], method = "range", range = c(0, 1))
      }
    }
  }

  return(cluserted_features)
}

# Calculate means
calculate_means <- function(features, cores) {

  # ignore warnings
  options(warn = -1)
  # Ignore Feature like time
  tryCatch(expr = {
    features_without_factors <- select(features, !one_of(c("Identifier", "day", "weekday", "hour")))
  })

  # IDs
  iterator <- distinct(features, Identifier)

  # Cluster
  cluster_of_cores <- makeCluster(cores)
  registerDoParallel(cluster_of_cores)

  # Build means per User/Host/Source
  means <- foreach(j = seq_along(iterator[, 1]), .packages = c("lubridate", "dplyr"), .combine = rbind) %dopar% {
    data_iter <- features_without_factors[(features$Identifier == iterator[j, 1]),]
    result <- data.frame()
    for (j in seq_len(ncol(features_without_factors))) {
      result[1, j] <- mean(data_iter[, j])
    }
    return(result)
  }
  stopCluster(cluster_of_cores)

  # Name means
  colnames(means) <- colnames(features_without_factors)

  return(list(iterator, means))
}

# Cluster
calculate_cluster <- function(iter_means, features, number_clusters, label, load_model, model_path, save_model, path) {

  # If a loaded model is used, its also needed to load the old cluster
  if (load_model) {
    cluster <- readRDS(file = paste0(model_path, "cluster.rds"))
    groups <- data.frame(Groups = as.numeric(cl_predict(cluster, iter_means[[2]], type = "class_id")))
  }else {
    # Seed + cluster data
    set.seed(123)
    cluster <- kmeans(iter_means[[2]], number_clusters, algorithm = "Hartigan-Wong", nstart = 100)

    # Extract cluster numbers as labels/feature
    groups <- data.frame(Groups = cluster[["cluster"]])
  }

  if (save_model) {
    saveRDS(cluster, paste0(path, "model/cluster.rds"))
  }

  # Feature -> first conditions else as Label
  if (label == F) {
    # Group ID and cluster number
    iterator <- data.frame(Identifier = iter_means[[1]], Gruppe = as.factor(groups[, 1]))

    # Join Features and iterator to add cluster numbers
    features <- left_join(features, iterator, by = "Identifier")
    # Construct unique IDs
    uniq_rownames <- make.names(features[, 1], unique = T)
    rownames(features) <- uniq_rownames
    features <- features[, -which(names(features) %in% "Identifier")]
    features <- features %>%
      rename(Identifier = Gruppe)
    return(features)
  }else {
    # Use it as Label
    labeled_mean_data <- data.frame(iter_means[[2]], Gruppe = as.factor(groups[, 1]))
    return(labeled_mean_data)
  }

}

# Calculates the max and min
calculate_min_max <- function(features, time_bin) {
  date_and_hour <- time_bin_day_and_hour
  if (time_bin == date_and_hour) {
    start <- 3
  }else {
    start <- 2
  }
  min_max <- data.frame()
  j <- 1
  for (i in seq_len(ncol(features[, start:(ncol(features) - 1)])) + start - 1) {
    min_max[j, 1] <- min(features[, i])
    min_max[j, 2] <- max(features[, i])
    j <- j + 1
  }
  return(min_max)
}

# Calcs the new min max if loaded model with existing min maxs are used
calculate_from_two_min_max <- function(min_max_loaded, min_max_new) {
  min_max <- data.frame()
  for (i in seq_len(ncol(min_max_loaded))) {
    min_max[i, 1] <- min(min_max_loaded[i, 1], min_max_new[i, 1])
    min_max[i, 2] <- max(min_max_loaded[i, 2], min_max_new[i, 2])
  }
  return(min_max)
}

normalize_features <- function(features, min, max) {

  min_max_normalize <- function(features, min, max) {
    return((features - min) / (max - min))
  }

  return(sapply(features, min_max_normalize, min = min, max = max))
}


complet_normalize_features <- function(features, min_max) {
  for (i in seq_len(ncol(features))) {
    features[, i] <- normalize_features(features[, i], min = min_max[i], max = min_max[ncol(features) + 1])
  }
  return(features)
}

#########################
# Statistical Functions #
#########################

data_statistics <- function(data, parsed_arguments, type) {
  statistics_path <- paste0(parsed_arguments$path, type, "_statistics/")
  dir.create(statistics_path)
  write_general_infos(data, statistics_path)
  plot_partition_logontype(data, statistics_path)
  plot_timeline_month(generate_timeline_month(data), statistics_path)
  generate_and_plot_timeline_day(data, statistics_path, parsed_arguments$startdate, parsed_arguments$enddate)
  write_users_with_most_logon_proportion(data, statistics_path)
}

plot_partition_logontype <- function(data, path) {
  logontype <- data.frame()
  for (i in 1:14 - 1) {
    logontype_x <- data[(data$Logon_Type == i),]
    logontype[i + 1, 1] <- i
    logontype[i + 1, 2] <- length(logontype_x[, 1])
  }
  logontype_plot <- ggplot(data = logontype, aes(x = logontype[, 1], y = logontype[, 2])) +
    geom_bar(stat = "identity") +
    xlab("Logon Type") +
    ylab("Count")

  suppressMessages(ggsave(paste0(path, "Logon_type.png"), logontype_plot, width = 10, dpi = 300, limitsize = F))
}


write_general_infos <- function(data, path) {
  infos <- NULL
  infos[1] <- paste("Existing Well known Source Ports:", paste(as.character(data[(data$Source_Port %in% 1:1023 &
    is.na(data$Source_Port) != T), "Source_Port"]), collapse = ", "))
  infos[2] <- paste("Number of Hosts:", nrow(group_by(data, data$Host) %>%
                                               summarise(n())))
  infos[3] <- paste("Number of Users:", nrow(group_by(data, data$User) %>%
                                               summarise(n())))
  infos[4] <- paste("Number of Source-IPs:", nrow(group_by(data, data$Source) %>%
                                                    summarise(n())))
  infos[5] <- paste("Smallest date of the data:", min(data$Time))
  infos[6] <- paste("Newest date:", max(data$Time))
  write.table(infos, file = paste0(path, "general_infos.txt"), row.names = F, col.names = F)
}

generate_timeline_month <- function(data) {
  i <- 0
  min_date <- as.Date(paste(year(min(data$Time)), month(min(data$Time)), "01", sep = "-"))
  max_date <- as.Date(paste(year(max(data$Time)), month(max(data$Time)), "01", sep = "-"))
  timeline <- data.frame()
  repeat {
    timeline[i + 1, 1] <- (min_date %m+% months(i))
    timeline[i + 1, 2] <- nrow(data[(data$Time >= (min_date %m+% months(i)) &
      (data$Time < (min_date %m+% months(i + 1)))),])

    if ((min_date %m+% months(i)) == max_date) {
      break
    }
    i <- i + 1
  }
  colnames(timeline) <- c("Time", "Count")

  return(timeline)
}

plot_timeline_month <- function(timeline, path) {
  timeplot <- ggplot(timeline, aes(x = Time, y = Count)) +
    geom_area(fill = "#69b3a2", alpha = 0.5) +
    geom_line()

  suppressMessages(ggsave(paste0(path, "Complet_timeseries_months.png"), timeplot, width = 50,
                          dpi = 300, limitsize = F))
}

calculate_start_and_enddate <- function(timeline) {
  timeline[, 3] <- scale(timeline[, 2])
  border <- as.numeric(quantile(timeline[, 3], (0.90 + nrow(timeline) * 0.00019)))
  left <- timeline[timeline[, 3] > border,]
  return(list(left[1, 1], as.Date(left[nrow(left), 1]) %m+% months(1)))
}

generate_and_plot_timeline_day <- function(data, path, startdate, enddate) {
  i <- 0
  timeline <- data.frame()
  repeat {
    timeline[i + 1, 1] <- (as.Date(startdate) %m+% days(i))
    timeline[i + 1, 2] <- nrow(data[(data$Time >= (as.Date(startdate) %m+% days(i)) &
      (data$Time < (as.Date(startdate) %m+% days(i + 1)))),])

    if ((as.Date(startdate) %m+% days(i)) == as.Date(enddate)) {
      break
    }
    i <- i + 1
  }

  colnames(timeline) <- c("Time", "Count")

  timeplot <- ggplot(timeline, aes(x = Time, y = Count)) +
    geom_area(fill = "#69b3a2", alpha = 0.5) +
    geom_line()

  suppressMessages(ggsave(paste0(path, "Quantil_timeseries_days.png"), timeplot, width = 50, dpi = 300, limitsize = F))
}

write_users_with_most_logon_proportion <- function(data, path) {
  logon_types <- distinct(data, data$Logon_Type)
  logons <- NULL
  for (i in logon_types[, 1]) {
    users_with_counts <- data[(data$Logon_Type == i),] %>%
      group_by(User) %>%
      summarise(n())
    users_with_counts <- users_with_counts[order(users_with_counts$`n()`, decreasing = T),]
    sum_logontype <- sum(users_with_counts$`n()`)
    users_with_counts[, 2] <- apply(users_with_counts[, 2], 2, function(x) { x / sum_logontype })
    users_with_counts <- slice(users_with_counts, 1:5)
    logons <- append(logons, paste0("Users with the most ", i, " Logon types:"))
    for (k in seq_len(nrow(users_with_counts))) {
      logons <- append(logons, paste("                                     ", users_with_counts[k, 1],
                                     users_with_counts[k, 2]))
    }
    logons <- append(logons, "")
  }
  write.table(logons, file = paste0(path, "Users_with_most_logon_types.txt"), row.names = F, col.names = F)
}

#----------------------------------------------------------------------------------------------------------------------------------------------------

# If the script start from console as link file, its needed to extract the path to the original path
detect_absolute_path_script <- function(file) {
  # Path to link file
  file_loc <- sub("[^/]*$", "", sub("--file=", "", file[grep("--file=.*", file)]))
  if (file_ext(file_loc) == "ln") {
    if (substring(file_loc, 1, 1) == ".") {
      path_exec <- system("pwd", intern = T)
      link_path <- paste0(path_exec, substring(file_loc, 2))
    }else {
      link_path <- substring(file_loc, 2)
    }
    # Relative path from link file to dir
    relativ_path <- Sys.readlink(paste0("/", link_path, "FindMaliciousEvents"))
    # Calculate absolute path
    absolute_path <- paste0(getAbsolutePath.default(sub("FindMaliciousEvents.R$", "", relativ_path),
                                                    workDirectory = paste0("/", link_path)), "/")
  }else {
    absolute_path <- paste0(getAbsolutePath.default(sub("FindMaliciousEvents.R$", "", file_loc),
                                                    workDirectory = paste0(system("pwd", intern = T))), "/")
  }
  return(absolute_path)
}

# Function for anomaly detection
anomaly_detection <- function(features, parsed_arguments, config_data) {
  machine_learning <- parsed_arguments$machine_learning
  path <- parsed_arguments$path
  data_path<-set_data_path_to_features(parsed_arguments)
  cores <- parsed_arguments$cores
  load_model <- parsed_arguments$load_model
  save_model <- parsed_arguments$save_model
  model_path <- parsed_arguments$model_path
  rank <- parsed_arguments$rank
  mean_rank <- parsed_arguments$mean_rank
  absolute_path <- parsed_arguments$absolute_path


  if (machine_learning == "IF" ||
    machine_learning == "kNN" ||
    machine_learning == "DAGMM") {
    setup_python(absolute_path)
    tryCatch(expr = {
      switch(machine_learning,
             "IF" = python_machine_learning_isolationforest(absolute_path, path,data_path, cores,
                                                            rank, mean_rank, load_model, save_model, model_path,
                                                            config_data = config_data[['isolationforest']]),
             "kNN" = python_machine_learning_kNN(absolute_path, path,data_path, cores,
                                                 rank, mean_rank, load_model, save_model, model_path,
                                                 config_data = config_data[['k_nearest_neigbhour']]),
             "DAGMM" = python_machine_learning_dagmm(absolute_path, path,data_path,
                                                     rank, mean_rank, load_model, save_model, model_path,
                                                     config_data = config_data[['deep_autoencoding_gaussian_mixture_model']])
      )
    }, error = function(e) {
      stop_and_help(paste0("An errror appeared into python script.\n", e), call. = F)
    })
  }else {
    machine_learning_randomforest(features, parsed_arguments$view, parsed_arguments$time_bin, cores,
                                  path, load_model, model_path, save_model,
                                  config_data = config_data[['randomforest']])
  }
}

set_data_path_to_features<-function (parsed_arguments){
  if(parsed_arguments$extracted_features){
        return(parsed_arguments$data_path)
  }else{
    return(paste0(parsed_arguments$path,"Features.csv"))
  }
}

load_machine_learning_config <- function(parsed_arguments) {
  config_file <- paste0(parsed_arguments$absolute_path, "config.yaml")
  validate_config_file(config_file)
  tryCatch(
    expr = {
      config_data <- read_yaml(config_file)
      return(config_data)
    }, error = function(e) {
      stop_and_help(paste0("The config file (", config_file, ") is not correct formated."), call. = F)
    }
  )
}

validate_config_file <- function(config_file) {
  if (file.exists(config_file) == F) {
    stop_and_help(paste0("The config file (", config_file, ") dont exists anymore."), call. = F)
  }else if (file.access(config_file, read_permission) == -1) {
    stop_and_help(paste0("The config file (", config_file, ") dont have read permissions."), call. = F)
  }else if (file_ext(config_file) != "yaml") {
    stop_and_help(paste0("The config file (", config_file, ") doesnt fit to .yaml file type."), call. = F)
  }
}

validate_config <- function(config_data, parsed_arguments, features) {
  switch(parsed_arguments$machine_learning,
         "IF" = validate_isolationforest_arguments(config_data),
         "kNN" = validate_knn_arguments(config_data, features),
         "DAGMM" = validate_dagmm_arguments(config_data, features),
         "RF" = validate_randomforest_arguments(config_data, features)
  )
}

validate_isolationforest_arguments <- function(config_data) {
  validate_machine_learning_method_exists(config_data, "isolationforest")
  hyperparameters <- c("n_estimators", "max_samples", "contamination", "max_features", "random_state")
  validate_machine_learning_hyperparamters_exist(config_data, "isolationforest", hyperparameters)
  validate_machine_learning_hyperparamters_isolationforest(config_data)
}

validate_knn_arguments <- function(config_data, features) {
  validate_machine_learning_method_exists(config_data, "k_nearest_neigbhour")
  hyperparameters <- c("contamination", "n_neighbors", "method", "algorithm", "metric")
  validate_machine_learning_hyperparamters_exist(config_data, "k_nearest_neigbhour", hyperparameters)
  validate_machine_learning_hyperparamters_k_nearest_neigbhour(config_data, features)
}

validate_dagmm_arguments <- function(config_data, features) {
  validate_machine_learning_method_exists(config_data, "deep_autoencoding_gaussian_mixture_model")
  hyperparameters <- c("comp_hiddens", "comp_activation", "est_hiddens", "est_activation", "est_dropout_ratio",
                       "epoch_size", "minibatch_size", "random_seed", "dynamic")
  validate_machine_learning_hyperparamters_exist(config_data, "deep_autoencoding_gaussian_mixture_model",
                                                 hyperparameters)
  validate_machine_learning_hyperparamters_deep_autoencoding_gaussian_mixture_model(config_data, features)
}

validate_randomforest_arguments <- function(config_data, features) {
  validate_machine_learning_method_exists(config_data, "randomforest")
  hyperparameters <- c("num.trees", "mtry", "min.node.size", "sample.fraction", "max.depth", "seed", "dynamic")
  validate_machine_learning_hyperparamters_exist(config_data, "randomforest", hyperparameters)
  validate_machine_learning_hyperparamters_randomforest(config_data, features)
}

validate_machine_learning_method_exists <- function(config_data, method) {
  if (is.null(config_data[[method]])) {
    stop_and_help(paste("The config for", method, "does not exists."), call. = F)
  }
}

validate_machine_learning_hyperparamters_exist <- function(config_data, method, hyperparameters) {
  for (i in seq_along(hyperparameters)) {
    if (is.null(config_data[[method]][[hyperparameters[i] ]])) {
      stop_and_help(paste("The config for hyperparameter", hyperparameters[i], "does not exists."), call. = F)
    }
  }
}

validate_machine_learning_hyperparamters_isolationforest <- function(config_data) {
  isolationforest_config_data <- config_data[['isolationforest']]
  validate_hyperparameter(isolationforest_config_data, "n_estimators", NULL, F, T, T, 0, 100000, F)
  validate_hyperparameter(isolationforest_config_data, "max_samples", "auto", F, T, F, 0, 1.0, F)
  validate_hyperparameter(isolationforest_config_data, "contamination", NULL, F, T, F, 0, 0.99999999, F)
  validate_hyperparameter(isolationforest_config_data, "max_features", NULL, F, T, F, 0, 1.0, F)
  validate_hyperparameter(isolationforest_config_data, "random_state", NULL, T, T, T, -Inf, Inf, F)
}

validate_machine_learning_hyperparamters_k_nearest_neigbhour <- function(config_data, features) {
  knn_config_data <- config_data[['k_nearest_neigbhour']]
  validate_hyperparameter(knn_config_data, "contamination", NULL, F, T, F, 0, .99999999, F)
  validate_hyperparameter(knn_config_data, "n_neighbors", NULL, F, T, T, 0, nrow(features), F)
  validate_hyperparameter(knn_config_data, "method", c("largest", "mean", "median"), F, F, F, NULL, NULL, F)
  validate_hyperparameter(knn_config_data, "algorithm", c("ball_tree", "kd_tree", "brute", "auto"), F, F, F, NULL, NULL, F)
  possible_metrics <- c('cityblock', 'cosine', 'euclidean', 'l1', 'l2', 'manhattan', 'braycurtis', 'canberra', 'chebyshev', 'correlation', 'dice', 'hamming', 'jaccard', 'kulsinski', 'mahalanobis', 'matching', 'minkowski', 'rogerstanimoto', 'russellrao', 'seuclidean', 'sokalmichener', 'sokalsneath', 'sqeuclidean', 'yule')
  validate_hyperparameter(knn_config_data, "metric", possible_metrics, F, F, F, NULL, NULL, F)
}

validate_machine_learning_hyperparamters_deep_autoencoding_gaussian_mixture_model <- function(config_data, features) {
  dagmm_config_data <- config_data[['deep_autoencoding_gaussian_mixture_model']]
  validate_hyperparameter(dagmm_config_data, "comp_hiddens", NULL, F, T, T, 0, Inf, T)
  activation_functions <- c("deserialize", "elu", "exponential", "gelu", "get", "hard_sigmoid", "linear", "relu", "selu", "serialize", "sigmoid", "softmax", "softplus", "softsign", "swish", "tanh")
  validate_hyperparameter(dagmm_config_data, "dynamic", possible_logic = T)
  validate_hyperparameter(dagmm_config_data, "comp_activation", activation_functions, F, F, F, NULL, NULL, F)
  validate_hyperparameter(dagmm_config_data, "est_hiddens", NULL, F, T, T, 0, Inf, T)
  validate_hyperparameter(dagmm_config_data, "est_activation", activation_functions, F, F, F, NULL, NULL, F)
  validate_hyperparameter(dagmm_config_data, "est_dropout_ratio", NULL, T, T, F, 0, 0.99999999, F)
  validate_hyperparameter(dagmm_config_data, "epoch_size", NULL, F, T, T, 99, Inf, F)
  validate_hyperparameter(dagmm_config_data, "minibatch_size", NULL, F, T, T, 0, nrow(features), F)
  validate_hyperparameter(dagmm_config_data, "random_seed", NULL, F, T, T, -Inf, Inf, F)
}

validate_machine_learning_hyperparamters_randomforest <- function(config_data, features) {
  randomforest_config_data <- config_data[['randomforest']]
  validate_hyperparameter(randomforest_config_data, "dynamic", possible_logic = T)
  validate_hyperparameter(randomforest_config_data, "num.trees", NULL, F, T, T, 0, 100000, F)
  validate_hyperparameter(randomforest_config_data, "mtry", NULL, F, T, T, 0, ncol(features), F)
  validate_hyperparameter(randomforest_config_data, "min.node.size", NULL, F, T, T, 0, Inf, F)
  validate_hyperparameter(randomforest_config_data, "sample.fraction", NULL, F, T, F, 0, 1.0, F)
  validate_hyperparameter(randomforest_config_data, "max.depth", NULL, T, T, T, 0, Inf, F)
  validate_hyperparameter(randomforest_config_data, "seed", NULL, T, T, T, -Inf, Inf, F)
}

validate_hyperparameter <- function(method_config_data, hyperparameter, possible_strings = NULL,
                                    possible_null = F, possible_number = F, integer = F, left_interval = NULL,
                                    right_interval = NULL, possible_vector = NULL, possible_logic = F) {
  if (is.character(method_config_data[[hyperparameter]])) {
    if ((method_config_data[[hyperparameter]] %in% possible_strings) == F) {
      stop_and_help(paste0("The Hyperparamter ", hyperparameter, " doesnt fit to the character option."))
    }
  }else if (possible_null == F && is.character(method_config_data[[hyperparameter]]) == F) {
    if (is.null(method_config_data[[hyperparameter]]) || (method_config_data[[hyperparameter]] == 0 &&
      (left_interval >= 0 || right_interval < 0))) {
      stop_and_help(paste0("The Hyperparamter ", hyperparameter, " cant use 0 and null."))
    }
  }else if (possible_number) {
    if (integer) {
      validate_hyperparamter_is_integer(method_config_data, hyperparameter)
    }else {
      validate_hyperparamter_is_double(method_config_data, hyperparameter)
    }
    validate_hyperprameter_interval(method_config_data, hyperparameter, left_interval, right_interval)
  }else if (possible_vector) {
    if (is.numeric(method_config_data[[hyperparameter]]) == F || is.vector(method_config_data[[hyperparameter]]) == F) {
      stop_and_help(paste0("The Hyperparamter ", hyperparameter, " needs to be a numeric vector."))
    }else if (is.unsorted(rev(method_config_data[[hyperparameter]]))) {
      stop_and_help(paste0("The Hyperparamter ", hyperparameter, " needs to be inverted sorted."))
    }else if (method_config_data[[hyperparameter]][[length(method_config_data[[hyperparameter]])]] <= 0) {
      stop_and_help(paste0("The last Array Hyperparamter ", hyperparameter, " needs to be bigger than zero."))
    }
  }else if (possible_logic) {
    if (is.logical(method_config_data[[hyperparameter]]) == F) {
      stop_and_help(paste0("The ", hyperparameter, " needs to be TRUE or FALSE."))
    }
  }
}

validate_hyperparamter_is_integer <- function(method_config_data, hyperparameter) {
  if (is.numeric(method_config_data[[hyperparameter]]) == F) {
    stop_and_help(paste0("The Hyperparamter ", hyperparameter, " is not a number."), call. = F)
  }else if (method_config_data[[hyperparameter]] %% 1 != 0) {
    stop_and_help(paste0("The Hyperparameter ", hyperparameter, " is not an integer."), call. = F)
  }
}

validate_hyperparamter_is_double <- function(method_config_data, hyperparameter) {
  if (is.double(method_config_data[[hyperparameter]]) == F) {
    stop_and_help(paste0("The Hyperparamter ", hyperparameter, " is not a double."), call. = F)
  }
}

validate_hyperprameter_interval <- function(method_config_data, hyperparameter, left_interval, right_interval) {
  if (method_config_data[[hyperparameter]] <= left_interval) {
    stop_and_help(paste0("The Hyperparamter ", hyperparameter, " is too small."), call. = F)
  }else if (method_config_data[[hyperparameter]] > right_interval) {
    stop_and_help(paste0("The Hyperparamter ", hyperparameter, " is too big."), call. = F)
  }
}


# Check if Python 3 is installed, if its installed activate a virtual envirmonent
setup_python <- function(path) {
  tryCatch(expr = {
    use_python(as.character(system("which python3", intern = T)))
  }, error = function(e) {
    stop_and_help("Python 3 is not installed.", call. = F)
  })
  tryCatch(expr = {
    use_virtualenv(paste0(path, "maliciousevents"), required = T)
  }, error = function(e) {
    stop_and_help(paste0("The PATH:", path, " is not containing the maliciousevents virtual environment."), call. = F)
  })
}

# Use python function with the isolationforest
python_machine_learning_isolationforest <- function(Input_path, Output_path,data_path, cores,
                                                    rank, mean_rank, load_model, save_model, model_path, config_data) {
  source_python(paste0(Input_path, "ml/IsolationForest_Anwendung.py"))
  isolationforest_exec(Output_path,data_path, as.integer(cores), rank, mean_rank, load_model, save_model, model_path, config_data)
}

# Use python function with the kNN
python_machine_learning_kNN <- function(Input_path, Output_path,data_path, cores,
                                        rank, mean_rank, load_model, save_model, model_path, config_data) {
  source_python(paste0(Input_path, "ml/kNN_Anwendung.py"))
  knn_exec(Output_path,data_path, as.integer(cores), rank, mean_rank, load_model, save_model, model_path, config_data)
}

# Use python function with the dagmm
python_machine_learning_dagmm <- function(Input_path, Output_path,data_path,
                                          rank, mean_rank, load_model, save_model, model_path, config_data) {
  source_python(paste0(Input_path, "ml/DAGMM_Anwendung.py"))
  dagmm_exec(Output_path,data_path, rank, mean_rank, load_model, save_model, model_path, config_data)
}

# Use function with the randomforest, to predict the number of clusters the view is visting
machine_learning_randomforest <- function(features, view, time_bin, cores,
                                          path, load_model, model_path, save_model, config_data) {
  #Clustert die Daten und gibt die Mittelwertdaten+ die Clusternummer als Label zurück
  means_label <- group_features(features, time_bin, cores, label = T, load_model, model_path, save_model, path)

  if (load_model) {
    model <- load_randomforest_model(model_path)
  }else if (config_data[["dynamic"]] == F) {
    model <- ranger(
      formula = Gruppe ~ .,
      data = means_label,
      num.trees = config_data[['num.trees']],
      mtry = config_data[['mtry']],
      min.node.size = config_data[['min.node.size']],
      sample.fraction = config_data[['sample.fraction']],
      max.depth = config_data[['max.depth']],
      seed = config_data[['seed']]
    )
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
    saveRDS(model, paste0(path, "model/", "model.rds"))
  }

  # Predict classes on the full data set
  tryCatch(
    expr = {
      preds <- predict(model, data = features[, colnames(means_label[-ncol(means_label)])], type = "response")
    }, error = function(e) {
      stop_and_help("The features of the data should be the same like the model features.", call. = F)
    }
  )
  # ID+Group
  id_with_associated_group <- data.frame(Identifier = features[, 1], Gruppe = as.factor(preds$predictions))

  # Counts how many groups are visted by the person and sorts it
  result <- id_with_associated_group %>%
    distinct(Identifier, Gruppe) %>%
    group_by(Identifier) %>%
    summarise(n())
  result <- as.data.frame(result[order(result$`n()`, decreasing = T),])
  # Write result
  write.csv(result, paste0(path, "results.csv"), row.names = F)
}

#Function to load a saved model
load_randomforest_model <- function(model_path) {
  model <- readRDS(paste0(model_path, "model.rds"))
  tryCatch(
    expr = {
      model_type <- attr(model$forest, "class")
      if (model_type != "ranger.forest") {
        stop_and_help("Missing the correct model on load with the correct machine learning option.", call. = F)
      }
    }, error = function(e) {
      stop_and_help("Missing the correct model on load with the correct machine learning option.", call. = F)
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
  train <- means_label[sample(seq_len(nrow(means_label)), nrow(means_label) * 0.7),]
  test <- means_label[!(rownames(means_label) %in% rownames(train)),]

  # Create hyperparameter grid
  hyper_grid <- create_hypergrid_for_gridsearch(ncol(means_label))

  # Iterate truth the net and calculate the accuracy
  for (i in seq_len(nrow(hyper_grid))) {

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

create_hypergrid_for_gridsearch <- function(cols_means) {
  hyper_grid <- expand.grid(
    mtry = seq(2, cols_means - 1, by = 1),
    node_size = seq(3, 9, by = 2),
    sampe_size = c(.55, .632, .70, .80),
    max_deph = seq(5, 14, by = 2),
    OOB_RMSE = 0,
    pred_test = 0
  )
  return(hyper_grid)
}

#############
# Visualize #
#############

visualization_results <- function(features, path, not_randomforest, rank, mean_rank) {

  results <- read.csv(paste0(path, "results.csv"))

  if (is.na(results[1, 1]) == F) {
    if ("hour" %in% colnames(features)) {
      features["hour"] <- as.numeric(seconds(as_hms(sapply(features["hour"], as.character))))
      results["hour"] <- as.numeric(seconds(as_hms(sapply(results["hour"], as.character))))
    }

    identifier <- data.frame(Identifier = sub("^X", "", sub("\\.[0-9]*$", "", results[, 1])))
    iterator <- distinct(identifier, Identifier = Identifier)
    if (not_randomforest == F || rank == T) {
      iterator <- iterator %>%
        slice(1:50)
    }

    path <- paste0(path, "Radarplots/")
    dir.create(path)

    palette <- colorRampPalette(colors = c("#000000", "#FFFFF0"))
    palette_outsider <- colorRampPalette(c("red", "purple"))
    set_plot_margin()
    for (i in seq_len(nrow(iterator))) {
      create_plot(results, features, iterator, i, not_randomforest, palette_outsider, palette, path, mean_rank)
    }
    delete_empty_directory(path)
  }else {
    cat("Nothing to plot, results are empty.", fill = 1)
  }
}

set_plot_margin <- function() {
  par(mar = c(1, 1, 2, 1))
  par(oma = c(0, 0, 0, 0))
}

create_plot <- function(results, features, iterator, i, not_randomforest, palette_outsider, palette, path, mean_rank) {
  tryCatch(
    expr = {
      extracted_insider_and_outsider <- extract_insider_and_outsider(not_randomforest, mean_rank, iterator[i, 1],
                                                                     results, features)
      outsider <- extracted_insider_and_outsider$outsider
      insider <- extracted_insider_and_outsider$insider
      colors <- extracted_insider_and_outsider$colors

      if (not_randomforest) {
        insider <- subset(insider, !(insider %in% outsider))
      }

      if (not_randomforest) {
        not_included <- c("Identifier", "day")
        if (mean_rank) {
          colors <- palette(length(colors))
          plot_data <- select(features[insider,], !one_of(not_included))
        }else {
          colors[1:(length(colors) - length(outsider))] <- palette((length(colors) - length(outsider)))
          colors[(length(colors) - length(outsider) + 1):length(colors)] <- palette_outsider(length(outsider))
          plot_data <- rbind(select(features[insider,], !one_of(not_included)),
                             select(features[outsider,], !one_of(not_included)))
        }
      }else {
        colors <- palette(nrow(insider))
        plot_data <- insider[-1]
      }


      colors_inside <- alpha(colors, 0.2)

      jpeg(paste0(path, i, "_", iterator[i, 1], ".jpg"), width = 1900, height = 1900, quality = 100,
           pointsize = 40, res = 120)
      radarchart(plot_data, maxmin = F, axistype = 1, pcol = colors, pfcol = colors_inside,
                 plwd = 1, plty = 2, cglty = 1, cglwd = 0.8, cglcol = "#466D3A", vlcex = 0.8, axislabcol = "#00008B")
      dev.off()
    }, error = function(e) {
      cat(paste0("No Radarplots for ", iterator[i, 1],
                 " generated, because there is just one Feature per view to be plotted."), fill = 1)
    }
  )
}

extract_insider_and_outsider <- function(not_randomforest, mean_rank, iterator, results, features) {
  if (not_randomforest) {
    if (mean_rank) {
      outsider <- ""
    }else {
      outsider <- grep(paste0("^X", iterator, "(\\.[0-9]+$){0,1}"), results[, 1], value = T)
    }
    insider <- grep(paste0("^X", iterator, "(\\.[0-9]+$){0,1}"), rownames(features), value = T)
    if (length(insider) > 50) {
      insider <- sample(insider, 50)
    }
    colors <- character(length(insider))
  }else {
    insider <- features[(features$Identifier == iterator),]
    outsider <- ""
    if (nrow(insider) > 50) {
      insider <- insider[sample(seq_len(nrow(insider)), 50),]
    }
    colors <- character(nrow(insider))
  }
  return(list(outsider = outsider, insider = insider, colors = colors))
}

delete_empty_directory <- function(path) {
  if (length(dir(path = path)) == 0) {
    unlink(path, recursive = T)
  }
}

# Calling main-function with the arguments
main(args)
