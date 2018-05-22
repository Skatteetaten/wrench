FROM aurora/turbo:feature_ATO_172_Turbo-SNAPSHOT

ARG baseImageVersion

LABEL maintainer="The Norwegian Tax Administration <utvpaas@skatteetaten.no>" \
      version=${BASE_IMAGE_VERSION} \
      no.skatteetaten.aurora.log.stdout="indexer"

ENV BASE_IMAGE_VERSION=${baseImageVersion} \
    NODE_TLS_REJECT_UNAUTHORIZED=0

WORKDIR ${HOME}

RUN microdnf install --nodocs gettext \
      nginx \
      nodejs  && \
    npm config set strict-ssl false && \
    npm config set registry http://aurora/npm/repository/npm-all/ && \
    npm install -g pm2 && \
#TODO: Check if we can make more restrictive permissions..... Nginx need this
    mkdir -p /u01/certs && \
    mkdir -p /var/cache/nginx && \
    mkdir -p /run/nginx && \
    chmod a=rwx /run/nginx && \
    chmod a=rwx /var/cache/nginx && \
    chmod a=rwx /var/run && \
    chmod -R a=rwx /var/lib/nginx && \
    chmod -R a=rwx /var/cache/nginx && \
    chmod -R a=rwx /var/log/nginx

COPY bin/liveness.sh /u01/application/bin/liveness.sh
COPY bin/readiness.sh /u01/application/bin/readiness.sh
COPY bin/run_node /u01/bin/run_node
COPY bin/run_nginx /u01/bin/run_nginx
COPY certs/* /u01/certs

ENV NODE_EXTRA_CA_CERTS=/u01/certs/bundle.pem \
    NODE_TLS_REJECT_UNAUTHORIZED=1

RUN cat /u01/certs/* > /u01/certs/bundle.pem && \
    chmod u=rwx,go=rx /u01/bin/run_node && \
    chmod u=rwx,go=rx /u01/bin/run_nginx && \
    mkdir /u01/.pm2 && \
    chmod a=rwx /u01/.pm2 && \
    chmod a=rw /etc/nginx/nginx.conf

