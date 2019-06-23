#! /bin/bash

# Just a temporary test script for the did-git-signing project

list=$(ls t[0-9]*.sh)

for test in $list; do
	sh -c "echo $test && ./$test | grep 'not ok' | grep -v 'TODO'" >> test.log 2>&1
	echo "[ $test ] --- Done"
done
