# The verifier archives are consensus dependencies, not optional substitutes.
# Builds without them retain the runtime fail-closed activation checks.
include(CheckCXXSourceCompiles)
include(CMakePushCheckState)

set(USDD_SP1_VERIFIER_ARCHIVE "" CACHE FILEPATH "Pinned USDD SP1 verifier static archive")
set(ECX_SP1_VERIFIER_ARCHIVE "" CACHE FILEPATH "ECX SP1 6.3.1 Groth16 and custody verifier static archive")
set(USDD_SP1_VERIFIER_NATIVE_LIBS "" CACHE STRING "USDD Rust archive native link libraries")
set(ECX_SP1_VERIFIER_SYSTEM_LIBS "" CACHE STRING "ECX Rust archive native link libraries")
add_library(drivechain_verifiers INTERFACE)

function(check_drivechain_archive archive)
  if(NOT IS_ABSOLUTE "${archive}" OR NOT EXISTS "${archive}" OR IS_DIRECTORY "${archive}" OR "${archive}" MATCHES "[ \t\r\n]")
    message(FATAL_ERROR "Verifier archive must be an existing absolute file path without whitespace: ${archive}")
  endif()
  if(APPLE)
    if(NOT CMAKE_OSX_DEPLOYMENT_TARGET)
      message(FATAL_ERROR "Set CMAKE_OSX_DEPLOYMENT_TARGET explicitly for verifier builds.")
    endif()
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    execute_process(
      COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/contrib/devtools/check_macos_deployment_target.py"
        --target "${CMAKE_OSX_DEPLOYMENT_TARGET}" "${archive}"
      RESULT_VARIABLE result
    )
    if(NOT result EQUAL 0)
      message(FATAL_ERROR "Verifier archive has a missing or mismatched macOS deployment target: ${archive}")
    endif()
  endif()
endfunction()

if(USDD_SP1_VERIFIER_ARCHIVE)
  check_drivechain_archive("${USDD_SP1_VERIFIER_ARCHIVE}")
  if(NOT USDD_SP1_VERIFIER_NATIVE_LIBS)
    if(APPLE)
      set(USDD_SP1_VERIFIER_NATIVE_LIBS "-framework Security;-framework CoreFoundation;iconv")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      set(USDD_SP1_VERIFIER_NATIVE_LIBS "dl;pthread;m")
    else()
      message(FATAL_ERROR "Set USDD_SP1_VERIFIER_NATIVE_LIBS for ${CMAKE_SYSTEM_NAME}.")
    endif()
  endif()
  cmake_push_check_state(RESET)
  set(CMAKE_REQUIRED_LIBRARIES "${USDD_SP1_VERIFIER_ARCHIVE}" ${USDD_SP1_VERIFIER_NATIVE_LIBS})
  unset(USDD_SP1_ABI_LINKS CACHE)
  check_cxx_source_compiles([[
    #include <cstddef>
    #include <cstdint>
    extern "C" {
    uint32_t usdd_sp1_verifier_abi_version(void);
    uint32_t usdd_sp1_verifier_semantic_identity_version(void);
    uint32_t usdd_sp1_verifier_semantic_identity(uint8_t*, size_t);
    uint32_t usdd_sp1_verify_annex(uint32_t, const uint8_t*, size_t,
      const uint8_t*, size_t, const uint8_t*, size_t);
    }
    int main() {
      uint8_t identity[32]{};
      return usdd_sp1_verifier_abi_version() + usdd_sp1_verifier_semantic_identity_version()
        + usdd_sp1_verifier_semantic_identity(identity, sizeof(identity))
        + usdd_sp1_verify_annex(0, nullptr, 0, nullptr, 0, nullptr, 0);
    }
  ]] USDD_SP1_ABI_LINKS)
  cmake_pop_check_state()
  if(NOT USDD_SP1_ABI_LINKS)
    message(FATAL_ERROR "The pinned USDD verifier ABI does not link. Check the archive and native libraries.")
  endif()
  set(HAVE_USDD_SP1_VERIFIER 1)
  target_compile_definitions(drivechain_verifiers INTERFACE HAVE_USDD_SP1_VERIFIER=1)
  target_link_libraries(drivechain_verifiers INTERFACE "${USDD_SP1_VERIFIER_ARCHIVE}" ${USDD_SP1_VERIFIER_NATIVE_LIBS})
endif()

if(ECX_SP1_VERIFIER_ARCHIVE)
  check_drivechain_archive("${ECX_SP1_VERIFIER_ARCHIVE}")
  if(NOT ECX_SP1_VERIFIER_SYSTEM_LIBS)
    if(APPLE)
      set(ECX_SP1_VERIFIER_SYSTEM_LIBS "iconv;System;c;m")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      set(ECX_SP1_VERIFIER_SYSTEM_LIBS "dl;pthread;m")
    else()
      message(FATAL_ERROR "Set ECX_SP1_VERIFIER_SYSTEM_LIBS for ${CMAKE_SYSTEM_NAME}.")
    endif()
  endif()
  cmake_push_check_state(RESET)
  set(CMAKE_REQUIRED_LIBRARIES "${ECX_SP1_VERIFIER_ARCHIVE}" ${ECX_SP1_VERIFIER_SYSTEM_LIBS})
  unset(ECX_SP1_ABI_LINKS CACHE)
  check_cxx_source_compiles([[
    #include <cstddef>
    #include <cstdint>
    extern "C" {
    bool ecx_sp1_6_3_1_verify_groth16_sha256(void*, const uint8_t*, size_t, const uint32_t*, const uint8_t*);
    bool ecx_witness_availability_verify_custody_receipts_v1(
      const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t);
    }
    int main() {
      const bool proof = ecx_sp1_6_3_1_verify_groth16_sha256(nullptr, nullptr, 0, nullptr, nullptr);
      const bool custody = ecx_witness_availability_verify_custody_receipts_v1(nullptr, 0, nullptr, 0, nullptr, 0);
      return proof || custody;
    }
  ]] ECX_SP1_ABI_LINKS)
  cmake_pop_check_state()
  if(NOT ECX_SP1_ABI_LINKS)
    message(FATAL_ERROR "ECX requires both the SP1 6.3.1 Groth16 and custody ABIs; another archive is not a substitute.")
  endif()
  set(ECX_ENABLE_SP1_GROTH16_VERIFIER 1)
  target_compile_definitions(drivechain_verifiers INTERFACE ECX_ENABLE_SP1_GROTH16_VERIFIER=1)
  target_link_libraries(drivechain_verifiers INTERFACE "${ECX_SP1_VERIFIER_ARCHIVE}" ${ECX_SP1_VERIFIER_SYSTEM_LIBS})
endif()
