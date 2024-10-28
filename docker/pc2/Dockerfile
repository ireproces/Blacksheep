FROM kathara/base

# This installs nginx service,
# installs samba service,
# installs nfs service,
# and installs rpcbind service which is needed for nfs to work
RUN apt update \
    && apt install nginx -y \
    && apt install samba -y \
    && apt install nfs-kernel-server -y \