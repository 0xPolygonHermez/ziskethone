# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file LICENSE.rst or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "/Users/jbaylina/git/zisk/zisk_eth_guest/cpp-guest/build-stub/_deps/evmone-build/deps/src/blst")
  file(MAKE_DIRECTORY "/Users/jbaylina/git/zisk/zisk_eth_guest/cpp-guest/build-stub/_deps/evmone-build/deps/src/blst")
endif()
file(MAKE_DIRECTORY
  "/Users/jbaylina/git/zisk/zisk_eth_guest/cpp-guest/build-stub/_deps/evmone-build/deps/src/blst-build"
  "/Users/jbaylina/git/zisk/zisk_eth_guest/cpp-guest/build-stub/_deps/evmone-build/deps"
  "/Users/jbaylina/git/zisk/zisk_eth_guest/cpp-guest/build-stub/_deps/evmone-build/deps/tmp"
  "/Users/jbaylina/git/zisk/zisk_eth_guest/cpp-guest/build-stub/_deps/evmone-build/deps/src/blst-stamp"
  "/Users/jbaylina/git/zisk/zisk_eth_guest/cpp-guest/build-stub/_deps/evmone-build/deps/src"
  "/Users/jbaylina/git/zisk/zisk_eth_guest/cpp-guest/build-stub/_deps/evmone-build/deps/src/blst-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/Users/jbaylina/git/zisk/zisk_eth_guest/cpp-guest/build-stub/_deps/evmone-build/deps/src/blst-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/Users/jbaylina/git/zisk/zisk_eth_guest/cpp-guest/build-stub/_deps/evmone-build/deps/src/blst-stamp${cfgdir}") # cfgdir has leading slash
endif()
