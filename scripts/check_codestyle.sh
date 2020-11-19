#!/usr/bin/env bash

TOOL=$(type -P pycodestyle)
if [ -z "${TOOL}" ]; then
	TOOL=$(type -P pep8)
fi
if [ -z "${TOOL}" ]; then
	echo "Either pycodestyle-3 or pep8 is required"
	exit 1
fi

${TOOL} --max-line-length=2000 --ignore=E741,W504 *.py $(find ./keylime ./test -name '*.py')
exit $?
