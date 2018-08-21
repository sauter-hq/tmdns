
EXTRA_DIST= init.DEBIAN init.PYNIX init.REDHAT init.SUSE init.MANDRAKE
CLEANFILES= initscript


all:	initscript

initscript:
	@if [ -f "init.$(DISTRIB)" ] ;\
	then \
		sed -e "s#!sbindir!#$(sbindir)#g" \
		    -e "s#!VERSION!#$(VERSION)#g" \
		    -e "s#!PID_FILE_DEFAULT!#$(PID_FILE_DEFAULT)#g" \
			< init.$(DISTRIB) > initscript ;\
	else \
	  echo ;\
	  echo ;\
	  echo "**********************************************************" ;\
	  echo "* There is no init-script for your $(DISTRIB) distribution." ;\
	  echo "* How about contributing one ?" ;\
	  echo "**********************************************************" ;\
	  echo ;\
	  echo ;\
	fi


install: initscript
	if [ -f initscript ] ;\
	then \
	  if [ ! -d "$(DESTDIR)$(INIT_DIR)" ] ;\
	  then \
	    mkdir -p "$(DESTDIR)$(INIT_DIR)" ;\
	  fi ;\
	  install -m 755 initscript $(DESTDIR)$(INIT_DIR)/tmdns ;\
	fi

