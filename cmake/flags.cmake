add_compile_options("/W0") # No warnings
add_compile_options("/GL-") # No whole program optimization
add_compile_options("/Od") # No optimization

add_link_options("/ENTRY:DriverEntry")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/dist")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/dist")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/dist")
