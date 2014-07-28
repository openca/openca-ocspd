#!/bin/sh

pkg=@PKGNAME@
rpm_build=`type -path rpmbuild`

arc=${pkg}-${ver}.tar.gz
spec="contrib/${pkg}.spec"

RPM_BASE=/usr/src/redhat
SOURCES=${RPM_BASE}/SOURCES
SRPMS=${RPM_BASE}/SRPMS
RPMS=${RPM_BASE}/RPMS

${rpm_build} -ta ${pkg}*.tar.gz

# rpm -ba ${spec}

mv ${RPMS}/*/${pkg}*.rpm .
mv ${SRPMS}/${pkg}*.rpm .

rm -f ${SOURCES}/${arc}

exit 0;
