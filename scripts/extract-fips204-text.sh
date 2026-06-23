#!/usr/bin/env sh
set -eu

mkdir -p tmp
pdftotext docs/NIST.FIPS.204.pdf tmp/fips204.txt
printf '%s\n' "Wrote tmp/fips204.txt"
