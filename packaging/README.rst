Packaging:
==========

This directory contains all the packaging scripts.

Debian Packaging:
-----------------
Install the required dependencies for creating the debian packages::
  $ apt-get install debhelper devscripts build-essential fakeroot
  $ cd vmware-nsx/packaging
  $ fakeroot debian/rules binary DEB_DESTDIR=/tmp/ BUILD_NUMBER=12334

This will publish debian package: neutron-plugin-nsx_2015.1.0_amd64.deb under
the /tmp directory
