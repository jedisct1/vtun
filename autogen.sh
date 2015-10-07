#! /bin/sh

aclocal && \
autoheader && \
autoconf && \
automake --add-missing 2> /dev/null
