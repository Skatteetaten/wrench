FROM node:boron
ARG baseImageVersion

MAINTAINER The Norwegian Tax Administration <utvpaas@skatteetaten.no>

LABEL version=${baseImageVersion}

ENV LANG=C.UTF-8 \
    HOME=/u01 \
    BASE_IMAGE_VERSION=${baseImageVersion}
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
RUN mkdir $HOME && \
    npm config set strict-ssl false && \
    npm config set registry http://aurora/npm/repository/npm-all/ && \
    npm install -g pm2

WORKDIR /u01

COPY bin/liveness.sh /u01/application/bin/liveness.sh
COPY bin/readiness.sh /u01/application/bin/readiness.sh
COPY bin/run /u01/bin/run
RUN chmod 755 /u01/bin/run && mkdir /u01/.pm2 && chmod 777 /u01/.pm2
