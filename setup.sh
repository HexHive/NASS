#!/bin/bash

if [ "$(dpkg --print-architecture)" = "arm64" ]; then
	cd fans && tar xvf _frida.abi3.so.tar.gz && cd ..
	cp Dockerfile Dockerfile_fans
	echo "COPY fans/_frida.abi3.so /usr/local/lib/python3.12/dist-packages/frida/_frida.abi3.so" >> Dockerfile_fans
	docker build . -t nass --file Dockerfile_fans
	exit 0
fi

docker build . -t nass

