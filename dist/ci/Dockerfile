# https://docs.docker.com/engine/reference/builder/
# Used for TEST_SUITE=distribution and deployment to OBS.

FROM opensuse/tumbleweed
MAINTAINER Jimmy Berry <jberry@suse.com>
LABEL akjsdhfiuv1zb8o07v2398u1=oihonpqbiuve

ADD valgrind-3.14.0-4.2.x86_64.rpm /
RUN rpm -i /valgrind-3.14.0-4.2.x86_64.rpm
RUN uname -a

RUN zypper -nv dup || :
RUN rm -rf /tmp/* /var/tmp/* /var/cache/* /var/log/*
RUN valgrind zypper -n -vvv ref -f
RUN valgrind zypper -n -vvv in --force valgrind
