# Wingnut

Cloud ready openjdk base image built using alpine targeted towards Kubernetes/Openshift

## How to use
This base image will trap the running of the script `$HOME/application/bin/start`
If you do not want this behavior then override the CMD directive

You can set the following ENV vars to control the behavior
 - REMOTE_DEBUG: turn on remote debuging on DEBUG_PORT (default 5005)
 - JAVA_MAX_MEM_RATIO: adjust the ratio of memory set as XMX. Default 80%
 - JAVA_DIAGNOSTICS: set this to turn on GC diagnostics
 - JAVA_CORE_LIMIT: Force the core limit to this value
 
When creating your `java` executable line in your start script make sure to include the `$JAVA_OPTS` ENV var

See example directory for a very basic Dockerfile that builds a java image

## How to build
./gradlew  buildImage

## How to push to registry
./gradlew pushImage --registry=<registry>

## Credits
The logic to calculate max memory and CPU is inspired from the work at 
https://github.com/fabric8io-images/java. Slightly tweaked to suit our needs in some places

## How to test
./gradlew testOutputImage