# These non-installed binaries deliberately support test chains. Never define
# ELEMENTS_FUNCTIONAL_TEST_ONLY on a production target or a shared dependency.
get_target_property(functional_node_sources bitcoin_node SOURCES)
get_target_property(functional_node_links bitcoin_node LINK_LIBRARIES)
add_library(elements_functional_test_node STATIC EXCLUDE_FROM_ALL ${functional_node_sources})
target_compile_definitions(elements_functional_test_node PRIVATE ELEMENTS_FUNCTIONAL_TEST_ONLY)
target_link_libraries(elements_functional_test_node PUBLIC ${functional_node_links})

add_executable(elements-functional-test-node bitcoind.cpp init/bitcoind.cpp)
target_compile_definitions(elements-functional-test-node PRIVATE ELEMENTS_FUNCTIONAL_TEST_ONLY)
target_link_libraries(elements-functional-test-node
  core_interface elements_functional_test_node $<TARGET_NAME_IF_EXISTS:bitcoin_wallet> secp256k1
)

foreach(tool cli tx util wallet)
  if(TARGET elements-${tool})
    get_target_property(tool_sources elements-${tool} SOURCES)
    get_target_property(tool_links elements-${tool} LINK_LIBRARIES)
    list(TRANSFORM tool_links REPLACE "^bitcoin_node$" "elements_functional_test_node")
    add_executable(elements-functional-test-${tool} ${tool_sources})
    target_compile_definitions(elements-functional-test-${tool} PRIVATE ELEMENTS_FUNCTIONAL_TEST_ONLY)
    target_link_libraries(elements-functional-test-${tool} ${tool_links})
  endif()
endforeach()
