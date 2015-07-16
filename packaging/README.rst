Packaging:
==========

This directory contains all the packaging scripts.

Debian Packaging:
-----------------
Install the required dependencies for creating the debian packages::
  $ apt-get install debhelper devscripts build-essential fakeroot
  $ cd vmware-nsx/packaging
  $ fakeroot debian/rules binary DEB_DESTDIR=/tmp BUILD_NUMBER=12334

This will publish debian package: neutron-plugin-nsx_<version>_<arch>.deb under
the /tmp directory
