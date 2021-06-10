#!/bin/bash
# This script attempts to build a docker image (based on Ubuntu 20.04) that
# checks out the NewCode code from GitHub and builds it following the
# instructions in the README.

set -euo pipefail

script="${BASH_SOURCE[0]}"
dir=$(dirname "$script")

docker build -t newnode "$dir"
