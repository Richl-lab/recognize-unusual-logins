#!/usr/bin/Rscript --vanilla

# Module:            Bachelor thesis
# Theme:             Detect Malicious Login Events
# Author:            Richard Mey <richard.mey@syss.de>
# Status:            19.07.2021

cpus <- as.integer(sub("[^0-9]+", "", system("lscpu | grep ^CPU\\(s\\)\\:", intern = T)))
repository <- "https://cran.r-project.org/"

options(Ncpus = cpus - 1)
.libPaths("~/.R")

tryCatch(expr = {
  cat("Installing required R packages, that could take some time to process.", fill = 1)
  packages <- c("dplyr",
                "ggplot2",
                "tools",
                "lubridate",
                "doParallel",
                "FactoMineR",
                "factoextra",
                "R.utils",
                "reticulate",
                "fmsb",
                "BBmisc",
                "ranger",
                "caret",
                "e1071",
                "clue",
                "yaml",
                "kernlab"
  )
  suppressMessages(install.packages(setdiff(packages, rownames(installed.packages())), repos = repository, quiet = T))
  write('.libPaths("~/.R")', file = file.path("~", ".Rprofile"), append = T)
}, error = function(e) {
  stop("Error on installing all required R packages.", e, call. = F)
}
)