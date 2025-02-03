#!/usr/bin/env bash

for PYLINT in pylint pylint-3; do
	if [ -n "$(type -P ${PYLINT})" ]; then
		break
	fi
done

if [ -z "$(type -P ${PYLINT})" ]; then
	echo "pylint or pylint-3 is required"
	exit 1
fi

${PYLINT} --version

PYTHONPATH="$(pwd)" ${PYLINT} \
	*.py \
	$(find ./keylime ./test ./scripts -name '*.py' ! -name 'oldtest.py' ! -path './keylime/da/examples/*.py')

exit $?
