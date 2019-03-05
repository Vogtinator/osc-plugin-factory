# https://docs.docker.com/engine/reference/builder/
# Used for TEST_SUITE=distribution and deployment to OBS.

FROM opensuse/tumbleweed
MAINTAINER Jimmy Berry <jberry@suse.com>

RUN uname -a
RUN zypper in valgrind
RUN zypper -nv dup
RUN zypper -n ref -f || true
RUN valgrind zypper -n ref -f
