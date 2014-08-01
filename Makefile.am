# file: Makefile.am
#
# © 2001-2009 by Massimiliano Pala and OpenCA Labs

VERSION			= @VERSION@
PKG_VER			= @PKG_VER@
PKG_MIN			= @PKG_MIN@
PACKAGE_NAME		= @PACKAGE_NAME@

#-------- installation paths: --------

srcdir			= @srcdir@
top_srcdir		= @top_srcdir@

DEST_BINDIR		= @bindir@
DEST_DATADIR		= @datadir@
DEST_INFODIR		= @infodir@
DEST_LIBDIR		= @libdir@
DEST_MANDIR		= @mandir@
DEST_SBINDIR		= @sbindir@

#-------- --------

## PRG_PREFIX		= openca-
## HAVE_SHARED_LIBS	= @HAVE_SHARED_LIBS@
POD2MAN			= @POD2MAN@
CHMOD			= @CHMOD@

#-------- user and group for installation: --------

openca_prefix		= @openca_prefix@

ACLOCAL_AMFLAGS		= -I m4

AUTOMAKE_OPTIONS = no-dependencies
SUBDIRS = src docs etc 

AUX_DIST = \
	$(ac_aux_dir)/acinclude.m4	\
	$(ac_aux_dir)/config.guess	\
	$(ac_aux_dir)/config.sub	\
	$(ac_aux_dir)/depcomp		\
	$(ac_aux_dir)/install-sh	\
	$(ac_aux_dir)/ltmain.sh		\
	$(ac_aux_dir)/missing		\
	$(ac_aux_dir)/mkinstalldirs

EXTRA_SCRIPTS = \
	contrib/autogen.sh \
	contrib/build-rpm.sh \
	contrib/openca-ocspd.spec

EXTRA_EXAMPLES = examples/index.txt examples/start.sh examples/request.sh \
	examples/ocspd.conf

INCLUDE_DIST = 

EXTRA_DIST = contrib/autogen.sh $(EXTRA_SCRIPTS) $(AUX_DIST) $(INCLUDE_DIST) \
	$(EXTRA_EXAMPLES) test

MAINTAINERCLEANFILES = Makefile.in aclocal.m4 configure \
	$(AUX_DIST)

bin_SCRIPTS = \
	scripts/ocspd-genreq.sh \
	test/test.sh

pkgconfig_DATA = contrib/openca-ocspd.pc

pkgconfigdir = @libdir@/pkgconfig

help::
		@$(ECHO) ""
		@$(ECHO) "make targets are:"
		@$(ECHO) "  <empty>         make everything OCSPD related"
		@$(ECHO) "  install         install package (into PREFIX dir)"
		@$(ECHO) "  clean           remove everything created by make"
		@$(ECHO) "  distclean       like clean, plus remove everything created by ./configure"
		@$(ECHO) "  dist            make distribution (.tar.gz) package"
		@$(ECHO) "  rpm             make distribution (.rpm) packages (requires rpmbuild)"
		@$(ECHO)


test:
	@cd test ; \
	./test.sh

install-data-local:
	@$(NORMAL_INSTALL)
	@$(mkinstalldirs) $(DESTDIR)$(exec_prefix)/var
	@$(mkinstalldirs) $(DESTDIR)$(exec_prefix)/var/run

distclean-local:
	@rm -rf autom4te.cache

########################################################
##               BEGIN RELEASE STUFF                  ##
########################################################

# PKG_VERSION=`cat VERSION | sed -e s/-[0-9a-zA-Z-]*//`
# MINOR=`cat VERSION | sed -e s/[0-9.]*-//`
MAKEFILE=Makefile
TODAY=`date +%Y%m%d`
INSTALL_BUILDER = @INSTALL_BUILDER@

snap:
	@$(MAKE) -f Makefile dist VERSION=SNAP-$(TODAY)

snaprpm: snap
	@$(MAKE) -f Makefile rpm VERSION="SNAP" RC="$(TODAY)"

rc1:
	@$(MAKE) -f Makefile dist VERSION=$(VERSION) RC="rc1"

rc1rpm:
	@$(MAKE) -f Makefile rpm RC="rc1"

rc2:
	@$(MAKE) -f Makefile dist VERSION=$(VERSION) RC="rc2"

rc2rpm:
	@$(MAKE) -f Makefile rpm RC="rc2"

rc3:
	@$(MAKE) -f Makefile dist VERSION=$(VERSION)-rc3

rc3rpm:
	@$(MAKE) -f Makefile rpm RC="rc3"


rpm:
	@echo
	@echo -n "Cleaning up old RPMs ... "
	@for i in $(PACKAGE_NAME)*.rpm ; do \
                rm -f $$i ; \
        done
	@echo "Done."
	@echo -n "Creating spec file ... " ; \
	filename="openca-ocspd.spec" ; \
	minor=$(RC) ; \
	[ -z "$$minor" ] && minor="1" ; \
	if [ -e "contrib/$$filename.orig" ] ; then \
		echo -n "($$filename.orig) --> "; \
		cat "contrib/$$filename.orig" | \
			sed -e "s/@RPM_VERSION@/$(PKG_VER)/g" | \
			sed -e "s/\@MINOR\@/$$minor/g" | \
			sed -e "s/\@RC\@/$$minor/g" | \
			sed -e "s/\@mybits\@/@mybits@/g" | \
			sed -e "s/@PKGNAME@/$(PACKAGE_NAME)/g" | \
			sed -e "s|@BUILDROOT@|/var/tmp/$(PACKAGE_NAME)-%{ver}-root|g" > \
			"contrib/openca-ocspd.spec" ; \
		echo "($$filename)"; \
	else \
		echo "contrib/$$filename.orig ... not found" ; \
		exit 1 ; \
	fi ; \
	echo "Building source package... " ; \
	$(MAKE) -f $(MAKEFILE) dist ; \
	echo "Building RPM package(s)... " ; \
	rm -rf /usr/src/redhat/BUILD/$(PACKAGE_NAME)* \
		$(HOME)/rpmbuild/BUILD/$(PACKAGE_NAME)* ; \
	sudo rpmbuild -ta $(PACKAGE_NAME)-$(VERSION).tar.gz ; \
	sudo mv /usr/src/redhat/RPMS/*/$(PACKAGE_NAME)*.rpm . 2>/dev/null || \
		sudo mv $(HOME)/tmp/rpm/RPMS/*/$(PACKAGE_NAME)*.rpm . 2>/dev/null || \
		sudo mv $(HOME)/rpmbuild/RPMS/*/$(PACKAGE_NAME)*.rpm . 2>/dev/null ; \
	sudo mv /usr/src/redhat/SRPMS/$(PACKAGE_NAME)*.src.rpm . 2>/dev/null || \
		sudo mv $(HOME)/tmp/rpm/SRPMS/$(PACKAGE_NAME)*.src.rpm . 2>/dev/null || \
		sudo mv $(HOME)/rpmbuild/SRPMS/$(PACKAGE_NAME)*.src.rpm . 2>/dev/null ; \
	echo

pkgbuild:
	@rm -rf /tmp/$(PACKAGE_NAME)-build-$(VERSION)
	@DESTDIR=/tmp/$(PACKAGE_NAME)-build-$(VERSION) ./configure --prefix=/usr
	@$(MAKE) -f Makefile
	@$(MAKE) DESTDIR=/tmp/$(PACKAGE_NAME)-build-$(VERSION) install
	@$(MAKE) -f Makefile pkgconfig

pkgconfig:
	@if [ "$(DIST_NAME)" = "darwin" ] ; then \
		IB_OUTPUT=`find $(HOME)/installbuilder*/ -maxdepth 1 -name output` ; \
		rm -rf $(PACKAGE_NAME)-*.app ; \
		$(INSTALL_BUILDER) build contrib/openca-ocspd.xml && \
		hdiutil create -srcfolder "$$IB_OUTPUT" \
			-volname "$(PACKAGE_NAME) v$(VERSION) Install" \
			"$(PACKAGE_NAME)-$(VERSION)-$(RC)-osx-$(ARCH_TARGET).dmg" ; \
		rm -r $$IB_OUTPUT/$(PACKAGE_NAME)-*.app ; \
	else \
		ret=`echo ${build_os} | grep 'solaris'`; \
		if [ $$? -eq 0 ] ; then \
		   IB_OUTPUT=`find $(HOME)/installbuilder*/* -name output` ; \
		else \
		   IB_OUTPUT=`find $(HOME)/installbuilder*/ -maxdepth 1 -name output` ; \
		fi ; \
		sudo $(INSTALL_BUILDER) build contrib/openca-ocspd.xml && \
		$(SHELL) -c "cp -r $$IB_OUTPUT/$(PACKAGE_NAME)-* ." ; \
			$(SHELL) -c "sudo rm -f $$IB_OUTPUT/$(PACKAGE_NAME)-*" ; \
	fi

########################################################
##                END RELEASE STUFF                   ##
########################################################

