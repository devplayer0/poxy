#!/bin/bash
shopt -s globstar

for s in cmd/**/*.go internal/**/*.go; do
    p="report/$s"
    mkdir -p "$(dirname $p)"
    sed 's/\t/  /g' < "$s" > "$p"
done

pandoc --filter pandoc-include-code --number-sections report.md -o report.pdf
