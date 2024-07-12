#!/bin/zsh

if [[ -z $1 ]]; then
  echo "Must supply a file to compile"
  exit 1
fi

scp -P 2222 tutil.S ubuntu@localhost:~
scp -P 2222 $1 ubuntu@localhost:~
ssh -p 2222 ubuntu@localhost "gcc ~/$1 ~/tutil.S -I. -I/usr/include/capstone -lcapstone -g -o rv-bin && ~/rv-bin"
