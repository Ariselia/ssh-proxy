project(ssh-proxy C)

set(proxy_SRCS
  ssh_adapter.c
  ssh_command.c
  ssh_compat.c
  ssh_packet.c
  
)

include_directories(
  ${LIBSSH_PUBLIC_INCLUDE_DIRS}
  ${CMAKE_BINARY_DIR}
)

add_executable(ssh-proxy ssh-proxy.c ${proxy_SRCS})
target_link_libraries(ssh-proxy ${MISC_SHARED_LIBRARY} ${LIBSSH_SHARED_LIBRARY})
