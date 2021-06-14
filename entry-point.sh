#!/bin/sh

# Workaround for GitLab ENTRYPOINT double execution (issue: 1380)
[ -f /tmp/gitlab-runner.lock ] && exit || >/tmp/gitlab-runner.lock

#echo java -jar /clj-scanner.jar "$@"

java -jar /clj-scanner.jar "$@"
