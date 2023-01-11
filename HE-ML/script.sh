#!/bin/bash

if [[ $# -eq 0 ]]; then
    echo 'No argument supplied'
    exit 0
fi

jupyter nbconvert --execute --to notebook $1
git add .
git commit -m "Result"
git push origin main
