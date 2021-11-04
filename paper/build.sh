#!/bin/sh

set -e

lualatex hctr2.tex
biber hctr2
lualatex hctr2.tex
lualatex hctr2.tex
