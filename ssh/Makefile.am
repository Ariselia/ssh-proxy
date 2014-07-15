include $(top_srcdir)/build/Makefile.defines

#INCLUDES           = -I /home/runtime/include -I$(top_srcdir)/include
noinst_LTLIBRARIES = libssh.la
libssh_la_SOURCES  = agent.c  auth.c \
		     base64.c buffer.c \
		     callbacks.c channels.c client.c config.c \
		     connect.c curve25519.c curve25519_ref.c \
		     dh.c ecdh.c error.c \
		     getpass.c init.c \
		     kex.c known_hosts.c \
		     legacy.c libcrypto.c log.c \
		     match.c messages.c misc.c \
		     options.c packet.c packet_cb.c packet_crypt.c pki.c poll.c \
		     session.c scp.c socket.c string.c threads.c wrapper.c \
		     sftp.c sftpserver.c \
		     auth1.c channels1.c crc32.c kex1.c packet1.c \
		     pki_crypto.c \
		     server.c bind.c \
		     gzip.c \
		     pthread.c

libssh_la_CFLAGS   = $(SP_CFLAGS)
libssh_la_LIBADD   = ../misc/libmisc.la -L/home/runtime/lib -lz
