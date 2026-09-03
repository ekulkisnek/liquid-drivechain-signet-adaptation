# Preserve the fork's public C ABI after upstream's removal of libconsensus.
include(GNUInstallDirs)

add_library(elementsconsensus_objects OBJECT
  script/bitcoinconsensus.cpp
  util/strencodings.cpp
  util/check.cpp
)
target_compile_definitions(elementsconsensus_objects PRIVATE BUILD_BITCOIN_INTERNAL)
target_link_libraries(elementsconsensus_objects PRIVATE core_interface bitcoin_consensus)

foreach(kind IN ITEMS SHARED STATIC)
  if(kind STREQUAL "SHARED")
    set(target elementsconsensus)
  else()
    set(target elementsconsensus_static)
  endif()
  add_library(${target} ${kind}
    $<TARGET_OBJECTS:elementsconsensus_objects>
    $<TARGET_OBJECTS:bitcoin_consensus>
    $<TARGET_OBJECTS:bitcoin_crypto>
    $<TARGET_OBJECTS:bitcoin_clientversion>
    $<TARGET_OBJECTS:elementssimplicity>
  )
  set_target_properties(${target} PROPERTIES OUTPUT_NAME elementsconsensus)
  target_link_libraries(${target} PRIVATE core_interface secp256k1 drivechain_verifiers)
  install(TARGETS ${target}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT elementsconsensus
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT elementsconsensus
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT elementsconsensus
  )
endforeach()
set_target_properties(elementsconsensus PROPERTIES VERSION 0.0.0 SOVERSION 0
  ARCHIVE_OUTPUT_NAME elementsconsensus_import)

install(FILES script/bitcoinconsensus.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  COMPONENT elementsconsensus)
install(FILES $<TARGET_FILE:secp256k1> DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RENAME ${CMAKE_STATIC_LIBRARY_PREFIX}elements-secp256k1${CMAKE_STATIC_LIBRARY_SUFFIX}
  COMPONENT elementsconsensus)

set(consensus_private_libs "-lelements-secp256k1")
foreach(verifier IN ITEMS USDD ECX)
  if(${verifier}_SP1_VERIFIER_ARCHIVE)
    string(TOLOWER ${verifier} name)
    install(FILES "${${verifier}_SP1_VERIFIER_ARCHIVE}"
      DESTINATION ${CMAKE_INSTALL_LIBDIR}
      RENAME ${CMAKE_STATIC_LIBRARY_PREFIX}elements-${name}-sp1-verifier${CMAKE_STATIC_LIBRARY_SUFFIX}
      COMPONENT elementsconsensus)
    string(APPEND consensus_private_libs " -lelements-${name}-sp1-verifier")
    if(verifier STREQUAL "USDD")
      set(native_libs ${USDD_SP1_VERIFIER_NATIVE_LIBS})
    else()
      set(native_libs ${ECX_SP1_VERIFIER_SYSTEM_LIBS})
    endif()
    foreach(lib IN LISTS native_libs)
      if(lib MATCHES "^-")
        string(APPEND consensus_private_libs " ${lib}")
      else()
        string(APPEND consensus_private_libs " -l${lib}")
      endif()
    endforeach()
  endif()
endforeach()
if(APPLE)
  string(APPEND consensus_private_libs " -lc++")
elseif(NOT MSVC)
  string(APPEND consensus_private_libs " -lstdc++ -lm")
endif()
set(prefix "\${pcfiledir}/../..")
set(exec_prefix "\${prefix}")
set(libdir "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
set(includedir "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
set(PACKAGE_NAME Elements)
set(PACKAGE_VERSION ${PROJECT_VERSION})
set(USDD_SP1_VERIFIER_PKGCONFIG_LIBS "${consensus_private_libs}")
set(ECX_SP1_VERIFIER_PKGCONFIG_LIBS "")
configure_file(${PROJECT_SOURCE_DIR}/libbitcoinconsensus.pc.in libelementsconsensus.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libelementsconsensus.pc
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig COMPONENT elementsconsensus)
