#!/usr/bin/env sh
set -eu

base='https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files'

for suite in \
  ML-DSA-keyGen-FIPS204 \
  ML-DSA-sigGen-FIPS204 \
  ML-DSA-sigVer-FIPS204
do
  mkdir -p "conformance/acvp/${suite}"
  for file in prompt.json expectedResults.json
  do
    curl -fsSL "${base}/${suite}/${file}" -o "conformance/acvp/${suite}/${file}"
  done
done
