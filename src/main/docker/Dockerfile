FROM node:8-alpine
ARG baseImageVersion

MAINTAINER The Norwegian Tax Administration <utvpaas@skatteetaten.no>

LABEL version=${baseImageVersion} \
      no.skatteetaten.aurora.log.stdout="indexer"

ENV LANG=C.UTF-8 \
    HOME=/u01 \
    BASE_IMAGE_VERSION=${baseImageVersion}
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
RUN mkdir $HOME && \
    apk update && \
    apk add nginx && \
    apk add bash && \
    rm /var/cache/apk/* && \
    npm config set strict-ssl false && \
    npm config set registry http://aurora/npm/repository/npm-all/ && \
    npm install -g pm2

WORKDIR /u01
#TODO: Check if we can make more restrictive permissions..... Nginx need this
RUN mkdir -p /u01/certs && \
    mkdir -p /var/cache/nginx && \
    mkdir -p /run/nginx && \
    chmod 777 /run/nginx && \
    chmod 777 /var/cache/nginx && \
    chmod 777 /var/run && \
    chmod -R 777 /var/lib/nginx && \
    chmod -R 777 /var/tmp/nginx && \
    chmod -R 777 /var/log/nginx

COPY bin/liveness.sh /u01/application/bin/liveness.sh
COPY bin/readiness.sh /u01/application/bin/readiness.sh
COPY bin/run_node /u01/bin/run_node
COPY bin/run_nginx /u01/bin/run_nginx
COPY certs/* /u01/certs
ENV NODE_EXTRA_CA_CERTS=/u01/certs/bundle.pem \
    NODE_TLS_REJECT_UNAUTHORIZED=1

RUN cat /u01/certs/* > /u01/certs/bundle.pem && \
    chmod 755 /u01/bin/run_node && \
    chmod 755 /u01/bin/run_nginx && \
    mkdir /u01/.pm2 && \
    chmod 777 /u01/.pm2
