# Copyright 2023 New Relic Corporation. All rights reserved.
# SPDX-License-Identifier: New Relic Pre-Release

verify_go_fmt() {
  needsFMT=$(gofmt -d .)
  if [ ! -z "$needsFMT" ]; then
    echo "$needsFMT"
    echo "Please format your code with \"gofmt .\""
    # exit 1
  fi
}

pwd=$(pwd)
version=$(go version)
echo $version
IFS=","

for dir in $DIRS; do
  cd "$pwd/$dir"

  # replace go-agent with local pull
  go mod edit -replace github.com/newrelic/csec-go-agent="$pwd"

  # manage dependencies
  go mod tidy

  go get
  # run tests
  if [[ $dir  ==  "instrumentation/csec_mongodb_mongo" ]]
  then
   go test -gcflags "-l" -race -benchtime=1ms -bench=. ./...
  else
   go test -race -benchtime=1ms -bench=. ./...
  fi
  
  go vet ./...
  verify_go_fmt

done