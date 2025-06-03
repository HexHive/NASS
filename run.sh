#!/bin/bash
docker run -it -v .:/NASS -v /var/run/docker.sock:/var/run/docker.sock --privileged --network host -w /NASS nass /bin/bash

