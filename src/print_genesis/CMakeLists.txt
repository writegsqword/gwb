# src/print_genesis/CMakeLists.txt

# 1) Define the executable with an explicit path to the source
add_executable(print_genesis
  ${CMAKE_CURRENT_SOURCE_DIR}/print_genesis.cpp
)

# 2) Link what monerod typically needs (safe superset for this helper)
target_link_libraries(print_genesis PRIVATE
  cryptonote_core
  cryptonote_basic
  ringct
  ringct_basic
  common
  device
  cncrypto
  version
  ${Boost_PROGRAM_OPTIONS_LIBRARY}
  ${Boost_FILESYSTEM_LIBRARY}
  ${Boost_THREAD_LIBRARY}
  ${CMAKE_THREAD_LIBS_INIT}
  ${EXTRA_LIBRARIES}
)

# 3) Optional: nicer output name/location
set_target_properties(print_genesis PROPERTIES
  OUTPUT_NAME "print-genesis"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# 4) Install (optional)
install(TARGETS print_genesis DESTINATION bin)
