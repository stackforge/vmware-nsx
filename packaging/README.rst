Packaging:
==========

This directory contains all the packaging scripts.

Debian Packaging:
-----------------
Install the required dependencies for creating debian packages::
  $ apt-get install debhelper devscripts build-essential


  $ cd vmware-nsx/packaging
  $ debian/rules binary DEB_DESTDIR=/tmp/ BUILD_NUMBER=12334

This will publish debian package: neutron-plugin-nsx_2015.1.0_amd64.deb under
/tmp directory

