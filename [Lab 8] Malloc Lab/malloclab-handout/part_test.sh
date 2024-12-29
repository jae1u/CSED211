#!/bin/bash
make clean
make
clear
./mdriver -V -f short1-bal.rep
echo "================================================================"
./mdriver -V -f short2-bal.rep
echo "================================================================"