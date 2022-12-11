#!/bin/bash
rm -rf output/*
docker build -t $1 .
docker run -it -v $PWD/output:/home/out -v $PWD/alerts:/root/input,type=bind $1:latest
# clean any dangling images/containers
docker rmi --force $(docker images -f dangling=true -q)

#while :; do echo 'Hit CTRL+C'; sleep 1; done
