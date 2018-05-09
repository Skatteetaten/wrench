FROM node:8-alpine
ARG baseImageVersion

MAINTAINER The Norwegian Tax Administration <utvpaas@skatteetaten.no>

LABEL version=${baseImageVersion} \
      no.skatteetaten.aurora.log.stdout="indexer"

# Docker Build Arguments
ARG RESTY_VERSION="1.13.6.1"
ARG RESTY_OPENSSL_VERSION="1.0.2k"
ARG RESTY_PCRE_VERSION="8.41"
ARG RESTY_J="1"
ARG RESTY_CONFIG_OPTIONS="\
    --with-file-aio \
    --with-http_addition_module \
    --with-http_auth_request_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_geoip_module=dynamic \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_image_filter_module=dynamic \
    --with-http_mp4_module \
    --with-http_random_index_module \
    --with-http_realip_module \
    --with-http_secure_link_module \
    --with-http_slice_module \
    --with-http_ssl_module \
    --with-http_stub_status_module \
    --with-http_sub_module \
    --with-http_v2_module \
    --with-http_xslt_module=dynamic \
    --with-ipv6 \
    --with-mail \
    --with-mail_ssl_module \
    --with-md5-asm \
    --with-pcre-jit \
    --with-sha1-asm \
    --with-stream \
    --with-stream_ssl_module \
    --with-threads \
    "
ARG RESTY_CONFIG_OPTIONS_MORE=""

# These are not intended to be user-specified
ARG _RESTY_CONFIG_DEPS="--with-openssl=/tmp/openssl-${RESTY_OPENSSL_VERSION} --with-pcre=/tmp/pcre-${RESTY_PCRE_VERSION}"


# 1) Install apk dependencies
# 2) Download and untar OpenSSL, PCRE, and OpenResty
# 3) Build OpenResty
# 4) Cleanup

RUN apk add --no-cache --virtual .build-deps \
        build-base \
        curl \
        gd-dev \
        geoip-dev \
        libxslt-dev \
        linux-headers \
        make \
        perl-dev \
        readline-dev \
        zlib-dev \
    && apk add --no-cache \
        gd \
        geoip \
        libgcc \
        libxslt \
        zlib \
    && cd /tmp \
    && curl -kfSL https://www.openssl.org/source/openssl-${RESTY_OPENSSL_VERSION}.tar.gz -o openssl-${RESTY_OPENSSL_VERSION}.tar.gz \
    && tar xzf openssl-${RESTY_OPENSSL_VERSION}.tar.gz \
    && curl -kfSL https://ftp.pcre.org/pub/pcre/pcre-${RESTY_PCRE_VERSION}.tar.gz -o pcre-${RESTY_PCRE_VERSION}.tar.gz \
    && tar xzf pcre-${RESTY_PCRE_VERSION}.tar.gz \
    && curl -kfSL https://openresty.org/download/openresty-${RESTY_VERSION}.tar.gz -o openresty-${RESTY_VERSION}.tar.gz \
    && tar xzf openresty-${RESTY_VERSION}.tar.gz \
    && cd /tmp/openresty-${RESTY_VERSION} \
    && ./configure -j${RESTY_J} ${_RESTY_CONFIG_DEPS} ${RESTY_CONFIG_OPTIONS} ${RESTY_CONFIG_OPTIONS_MORE} \
    && make -j${RESTY_J} \
    && make -j${RESTY_J} install \
    && cd /tmp \
    && rm -rf \
        openssl-${RESTY_OPENSSL_VERSION} \
        openssl-${RESTY_OPENSSL_VERSION}.tar.gz \
        openresty-${RESTY_VERSION}.tar.gz openresty-${RESTY_VERSION} \
        pcre-${RESTY_PCRE_VERSION}.tar.gz pcre-${RESTY_PCRE_VERSION} \
    && apk del .build-deps \
    && ln -sf /dev/stdout /usr/local/openresty/nginx/logs/access.log \
    && ln -sf /dev/stderr /usr/local/openresty/nginx/logs/error.log

# Add additional binaries into PATH for convenience
ENV PATH=$PATH:/usr/local/openresty/luajit/bin:/usr/local/openresty/nginx/sbin:/usr/local/openresty/bin

# lua-resty-openidc installation - including deps
RUN apk update
RUN apk add \
        alpine-sdk \
        lua5.1 \
        lua5.1-dev \
        openssl \
        openssl-dev \
        gcc \
        curl \
        git

RUN git config --global url."https://".insteadOf git://
RUN apk add \
        luarocks5.1 

RUN cd /usr/bin 
RUN luarocks-5.1 install lua-resty-http 
RUN luarocks-5.1 install lua-resty-session 
RUN luarocks-5.1 install lua-resty-jwt \
    &&  luarocks-5.1 install luacrypto \
    &&  luarocks-5.1 install lua-resty-hmac \
    &&  luarocks-5.1 install lua-resty-openidc


# Copy nginx configuration files
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY nginx.vh.default.conf /etc/nginx/conf.d/default.conf

#CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]


ENV LANG=C.UTF-8 \
    HOME=/u01 \
    BASE_IMAGE_VERSION=${baseImageVersion}
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
RUN mkdir $HOME && \
    apk update && \
    apk add bash && \
    apk add gettext && \
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
    chmod 777 /var/run 
    # && \
    # chmod -R 777 /var/lib/nginx && \
    # chmod -R 777 /var/tmp/nginx && \
    # chmod -R 777 /var/log/nginx

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
    # && \
    # chmod 666 /etc/nginx/nginx.conf

