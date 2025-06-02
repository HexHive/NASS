FROM ubuntu:18.04

RUN apt-get update && apt-get install rsync git-core gnupg flex bison build-essential zip curl zlib1g-dev libc6-dev-i386 x11proto-core-dev libx11-dev lib32z1-dev libgl1-mesa-dev libxml2-utils xsltproc unzip fontconfig -y
RUN apt-get update && apt-get install python python-pip graphviz -y
RUN pip install --user xmljson 
RUN pip install --user lxml
COPY __init__.py /root/.local/lib/python2.7/site-packages/xmljson/__init__.py
