
EXTRA_DIST=update-resolvrdv register-service.in
sbin_SCRIPTS= update-resolvrdv register-service
DISTCLEANFILES=register-service


register-service: register-service.in
	sed -e "s#!PERL!#$(PERL)#g" \
	    -e "s#!DYNAMIC_SERVICE_FILE_DEFAULT!#$(DYNAMIC_SERVICE_FILE_DEFAULT)#g" \
	       < $(srcdir)/register-service.in > register-service
	chmod 755 register-service

