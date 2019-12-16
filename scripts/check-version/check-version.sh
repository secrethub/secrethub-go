#!/bin/bash

BRANCH=$(git rev-parse --abbrev-ref HEAD)
RELEASE_PREFIX="release/"

if [[ $BRANCH == ${RELEASE_PREFIX}* ]]
then
  VERSION=${BRANCH#"$RELEASE_PREFIX"}
  go run ./scripts/check-version/main.go "${VERSION}"
else
  echo "Not on a release branch, skipping version check."
fi
