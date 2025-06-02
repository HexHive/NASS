#!/bin/bash

if [ -z "$1" ]; then
	  echo "path to the aosp directory pls!"
	  exit
fi

set -x

mkdir backup
cp "$1/frameworks/av/media/libmediaplayerservice/MediaPlayerService.cpp" backup/
cp "$1/frameworks/av/media/libmediametrics/MediaAnalyticsItem.cpp" backup/
cp "$1/frameworks/native/libs/gui/IProducerListener.cpp" backup/
cp "$1/frameworks/av/media/libmediaplayer2/mediaplayer2.cpp" backup/
cp "$1/frameworks/av/media/libmedia/mediaplayer.cpp" backup/
cp "$1/frameworks/native/services/surfaceflinger/SurfaceFlinger.cpp" backup/


cp misc/MediaPlayerService.cpp "$1/frameworks/av/media/libmediaplayerservice/MediaPlayerService.cpp"
cp misc/MediaAnalyticsItem.cpp "$1/frameworks/av/media/libmediametrics/MediaAnalyticsItem.cpp"
cp misc/IProducerListener.cpp "$1/frameworks/native/libs/gui/IProducerListener.cpp"
cp misc/mediaplayer2.cpp "$1/frameworks/av/media/libmediaplayer2/mediaplayer2.cpp"
cp misc/mediaplayer.cpp "$1/frameworks/av/media/libmedia/mediaplayer.cpp"
cp misc/SurfaceFlinger.cpp "$1/frameworks/native/services/surfaceflinger/SurfaceFlinger.cpp"
