# file: (src/modules/openca-sv/)docs/Makefile
#
# © 2001-2011 OpenCA Group

MANLEV=3

PODS		= ocspd.3.pod ocspd.conf.3.pod
man_MANS 	= ocspd.3 ocspd.conf.3
EXTRA_DIST 	= $(man_MANS) $(PODS)

POD2MAN		= @POD2MAN@
POD2HTML	= @POD2HTML@
POD_MANS	= $(PODS:%.pod=%)
POD_HTML	= $(PODS:%.html=%)

SUFFIXES	= .pod

#---- variable settings above, rules below ----

.PHONY:	default

all: default

default::	man

man::		$(POD_MANS)

.pod:
	$(POD2MAN) --section=3 \
		--c "OpenCA Contributed Manual" \
		--r "openca-ocspd @VERSION@" $< > $@

.html:
	$(POD2HTML) $< >$@

install-man::
	@$(mkinstalldirs) $(DESTDIR)$(exec_prefix)
	@$(mkinstalldirs) $(DESTDIR)$(exec_prefix)/share
	@$(mkinstalldirs) $(DESTDIR)$(exec_prefix)/share/man
	@$(mkinstalldirs) $(DESTDIR)$(exec_prefix)/share/man/man$(MANLEV)
	@echo "Installing Man pages is $(DESTDIR)$(exec_prefix)/share/man/man$(MANLEV) ... "
	@for file in $(man_MANS) ; do \
       if test -f $$file ; then \
        $(INSTALL_DATA) $$file $(DESTDIR)$(exec_prefix)/share/man/man$(MANLEV) ; \
       fi ; \
    done
	@echo "Done. Add $(DESTDIR)$(exec_prefix)/share/man to MANPATH."

# install-data-am: install-man
# 	@$(NORMAL_INSTALL) ; \
 #        $(mkinstalldirs) $(DESTDIR)$(exec_prefix)/share; \
  #       $(mkinstalldirs) $(DESTDIR)$(exec_prefix)/share/openca-ocspd; \
   #      for file in $(EXTRA_DIST); do \
    #         if test -f $$file; then \
     #          $(INSTALL_DATA) $$file $(DESTDIR)$(exec_prefix)/share/openca-ocspd; \
      #       fi \
       #    done

clean:
	@rm -rf $(man_MANS)
