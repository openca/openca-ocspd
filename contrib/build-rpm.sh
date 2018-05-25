#!/bin/sh

pkg=@PKGNAME@
rpm_build=`type -path rpmbuild`

arc=${pkg}-${ver}.tar.gz
spec="contrib/${pkg}.spec"

RPM_BASE=${HOME}/rpmbuild
SOURCES=${RPM_BASE}/SOURCES
SRPMS=${RPM_BASE}/SRPMS
RPMS=${RPM_BASE}/RPMS

${rpm_build} "--build-root=$RPM_BASE" -ta ${pkg}*.tar.gz

# rpm -ba ${spec}

mv ${RPM_BASE}/${RPMS}/*/${pkg}*.rpm .
mv ${RPM_BASE}/${SRPMS}/${pkg}*.rpm .

rm -f ${RPM_BASE}/${SOURCES}/${arc}

exit 0;
