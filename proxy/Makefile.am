include $(top_srcdir)/build/Makefile.defines

#INCLUDES            = -I /home/runtime/include -I$(top_srcdir)/include
noinst_LTLIBRARIES  = libproxy.la
libproxy_la_SOURCES = ssh-proxy.c ssh_misc.c \
                      ssh_adapter.c ssh_command.c ssh_compat.c ssh_packet.c 

libproxy_la_CFLAGS  = $(SP_CFLAGS)

libproxy_la_LIBADD  = ../misc/libmisc.la ../ssh/libssh.la
