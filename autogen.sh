#!/bin/sh
set -e

# Install 'install-sh' and do not bother with missing 'Makefile.am'
automake --add-missing --copy 2>/dev/null || true

autoreconf -vif
