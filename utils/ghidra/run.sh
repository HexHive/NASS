#!/bin/sh

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <path_to_bin> <script_to_run> <input_path> <output_path>"
    exit 1
fi

analyzeHeadless $(mktemp -d) HeadlessAnalysis -overwrite -import $1 -scriptPath $(pwd) -prescript setup_project.py -postscript $2 ++input $3 ++output $4
