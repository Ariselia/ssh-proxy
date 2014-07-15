include $(top_srcdir)/build/Makefile.defines

noinst_PROGRAMS     = tssh tsshd thashtable
thashtable_SOURCES  = test-hashtable.c
thashtable_INCLUDES = -I(top_srcdir)/include
thashtable_CFLAGS   =  $(SP_CFLAGS)
thashtable_LDADD    = ../misc/libmisc.la -lrt

tssh_SOURCES        = ssh.c knownhosts.c authentication.c
tssh_INCLUDES       = -I /home/runtime/include -I(top_srcdir)/include
tssh_CFLAGS         =  $(SP_CFLAGS)
tssh_LDADD          = ../ssh/libssh.la -L/home/runtime/lib -lssl -lcrypto -lpthread -lz

tsshd_SOURCES       = sshd-cb.c
tsshd_INCLUDES      = -I /home/runtime/include -I(top_srcdir)/include
tsshd_CFLAGS        =  $(SP_CFLAGS)
tsshd_LDADD         = ../ssh/libssh.la -L/home/runtime/lib -lssl -lcrypto -lpthread -lz

