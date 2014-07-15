AUTOMAKE_OPTIONS   = dist-bzip2 foreign 1.9
SUBDIRS            = misc ssh samples proxy
ACLOCAL_AMFLAGS    = -I m4
RELEASE            = -release 1.0
VERSION_INFO       = 0:0:0
bin_PROGRAMS       = ssh-proxy
ssh_proxy_SOURCES  = 
EXTRA_DIST         =

ssh_proxy_INCLUDES = -I /home/runtime/include -I ./include
ssh_proxy_CFLAGS   =  $(ssh_proxy_INCLUDES)
ssh_proxy_LDADD    = misc/libmisc.la ssh/libssh.la proxy/libproxy.la $(LIBAIO_LIBS) -laio_openssl -L/home/runtime/lib -lssl -lcrypto -lpthread

ssh_proxy_LDFLAGS = -static
