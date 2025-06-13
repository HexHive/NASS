#!/bin/bash

if [ "$(dpkg --print-architecture)" = "arm64" ]; then
	cd fans && tar xvf _frida.abi3.so.tar.gz && cd ..
	echo "COPY fans/_frida.abi3.so /usr/local/lib/python3.12/dist-packages/frida/_frida.abi3.so" >> Dockerfile
fi

docker build . -t nass

