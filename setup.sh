#!/bin/bash
git clone https://github.com/HexHive/NASS.git
cd NASS && git pull && cd ..
docker build . -t nass

