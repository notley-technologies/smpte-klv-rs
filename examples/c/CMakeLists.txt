# Build the examples against an installed smpte_klv package.
#
#   cmake -S examples/c -B build -DCMAKE_PREFIX_PATH=/usr/local
#   cmake --build build
#
# -DSMPTE_KLV_STATIC=ON links the static library instead.
cmake_minimum_required(VERSION 3.10)
project(smpte_klv_examples C)

option(SMPTE_KLV_STATIC "Link smpte_klv statically" OFF)
find_package(smpte_klv 0.1 REQUIRED)

if(SMPTE_KLV_STATIC)
  set(klv_library smpte_klv::smpte_klv_static)
else()
  set(klv_library smpte_klv::smpte_klv)
endif()

foreach(example klv_dump klv_encode)
  add_executable(${example} ${example}.c)
  target_link_libraries(${example} PRIVATE ${klv_library})
endforeach()
