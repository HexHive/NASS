FROM ubuntu:24.04

RUN apt-get update && apt-get install -y docker.io python3 python3-pip wget curl unzip git adb jq && rm -rf /var/lib/apt/lists/*


RUN --mount=type=bind,source=./requirements.txt,target=/tmp/requirements.txt \
    pip3 install -r /tmp/requirements.txt --break-system-packages

RUN wget https://dl.google.com/android/repository/android-ndk-r27c-linux.zip
RUN unzip android-ndk-r27c-linux.zip
