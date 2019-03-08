# https://docs.docker.com/engine/reference/builder/
# Used for TEST_SUITE=distribution and deployment to OBS.

FROM opensuse/tumbleweed
MAINTAINER Jimmy Berry <jberry@suse.com>
LABEL akjsdhfiuv1zb8o07v2398u1=oihonpqbiuve

ADD valgrind-3.14.0-4.2.x86_64.rpm /
RUN rpm -i /valgrind-3.14.0-4.2.x86_64.rpm

RUN uname -a

RUN zypper -nv in libzypp || :
RUN rm -rf /tmp/* /var/tmp/* /var/cache/* /var/log/*
RUN valgrind --exit-on-first-error=yes --error-exitcode=42 zypper -n -vvv ref -f

RUN zypper -nv in glibc || :
RUN rm -rf /tmp/* /var/tmp/* /var/cache/* /var/log/*
RUN valgrind --exit-on-first-error=yes --error-exitcode=42 zypper -n -vvv ref -f

RUN zypper -nv in libcurl4 || :
RUN rm -rf /tmp/* /var/tmp/* /var/cache/* /var/log/*
RUN valgrind --exit-on-first-error=yes --error-exitcode=42 zypper -n -vvv ref -f || :

ADD libcurl4-7.64.0-257.1.x86_64.rpm /
RUN rpm -i --nodigest --nosignature /libcurl4-7.64.0-257.1.x86_64.rpm
RUN rm -rf /tmp/* /var/tmp/* /var/cache/* /var/log/*
RUN zypper -n -vvv ref -f || :

ADD libzypp-17.11.2-7.1.x86_64.rpm /
RUN rpm -i --nodigest --nosignature /libzypp-17.11.2-7.1.x86_64.rpm
RUN rm -rf /tmp/* /var/tmp/* /var/cache/* /var/log/*
RUN valgrind --exit-on-first-error=yes --error-exitcode=42 zypper -n -vvv ref -f || :
