# https://docs.docker.com/engine/reference/builder/
# Used for TEST_SUITE=distribution and deployment to OBS.

FROM opensuse/tumbleweed
MAINTAINER Jimmy Berry <jberry@suse.com>
LABEL akjsdhfiuv1zb8o07v2398u1=oihonpqbiuve

ADD valgrind-3.14.0-4.2.x86_64.rpm /
RUN rpm -i /valgrind-3.14.0-4.2.x86_64.rpm
RUN uname -a

RUN zypper -n in libzypp libcurl4 zypper
RUN zypper -n in file-magic gpg2 libassuan0 libcrypt1 libdw1 libebl-plugins libelf1 libmagic1
RUN zypper -n in openSUSE-release openSUSE-release-ftp

RUN zypper -n in glibc grep libaugeas0 libgnutls30 libncurses6 libpsl5 libssh4
RUN valgrind zypper -n -vvv ref -f

RUN zypper -n in libsystemd0 libudev1 ncurses-utils openSUSE-build-key terminfo-base
RUN valgrind zypper -n -vvv ref -f

