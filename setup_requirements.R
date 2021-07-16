#!/usr/bin/Rscript --vanilla

# Module:            Bachelor thesis
# Theme:             Detect Malicious Login Events
# Author:            Richard Mey <richard.mey@syss.de>
# Status:            06.07.2021

repository <- "https://cran.r-project.org/"
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
  write('.libPaths("~/.R")', file=file.path("~",".Rprofile"),append = T)
}, error = function(e) {
  stop("Error on installing all required R packages.", e, call. = F)
}
)