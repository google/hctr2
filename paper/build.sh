#!/bin/sh

set -e

cd "$(dirname "$0")"

LATEX="lualatex --interaction=nonstopmode --halt-on-error"

${LATEX} hctr2.tex
biber hctr2
${LATEX} hctr2.tex
${LATEX} hctr2.tex
