#!bin/bash
NAME="vtun"
ARCH=`uname -m`
if [ $ARCH == 'x86_64' ]
then
TAG="latest"
elif [ $ARCH == 'aarch64' ]
then
TAG="arm64"
else
TAG=$ARCH
fi
echo "build $NAME:$TAG"
docker build . -t netbyte/$NAME:$TAG
docker image push netbyte/$NAME:$TAG

echo "DONE!!!"
