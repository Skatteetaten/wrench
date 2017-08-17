# Wrench

Image with Nodejs and Nginx for Webapplications

## How to use

This image is used by Architect to create Webleveransepakke-images

The image can run in to modi, node or nginx. The corresponding start scripts are:

- /u01/bin/run_node: Starts Node through pm2
- /u01/bin/run_nginx: Starts Nginx

This image should be used as a base for application images.

## How to build
./gradlew  buildImage

## How to push to registry
./gradlew pushImage --registry=<registry>

## How to test
./gradlew testOutputImage
