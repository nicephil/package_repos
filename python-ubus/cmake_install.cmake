# Install script for directory: /home/llwang/repos/x86/osdk_repos/build_dir/target-i386_pentium4_musl-1.1.16/ubus-2017-02-18-34c6e818/python

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

if("${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  execute_process(COMMAND /home/llwang/repos/x86/osdk_repos/staging_dir/host/bin/cmake -E env "CC=/home/llwang/repos/x86/osdk_repos/staging_dir/toolchain-i386_pentium4_gcc-5.4.0_musl-1.1.16/bin/i486-openwrt-linux-musl-gcc " "LDSHARED=/home/llwang/repos/x86/osdk_repos/staging_dir/toolchain-i386_pentium4_gcc-5.4.0_musl-1.1.16/bin/i486-openwrt-linux-musl-gcc  -shared" "CFLAGS=-Os -Wall -Werror --std=gnu99 -g3 -fno-strict-aliasing -I.. -I/home/llwang/repos/x86/osdk_repos/staging_dir/target-i386_pentium4_musl-1.1.16/usr/include/python2.7 -DUBUS_UNIX_SOCKET=\\\"/var/run/ubus.sock\\\"" /home/llwang/repos/x86/osdk_repos/staging_dir/target-i386_pentium4_musl-1.1.16/host/bin/python /home/llwang/repos/x86/osdk_repos/build_dir/target-i386_pentium4_musl-1.1.16/ubus-2017-02-18-34c6e818/python/setup.py install --prefix=/usr)
endif()

