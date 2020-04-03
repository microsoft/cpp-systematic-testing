include_directories("../include")

set(src_files "systematic_testing.cc")

add_library(systest SHARED ${src_files})
set_target_properties(systest PROPERTIES
    OUTPUT_NAME "systest"
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin/")
target_compile_definitions(systest PUBLIC SYSTEST_SHARED SYSTEST_EXPORT SYSTEST_AS_LIBRARY)

add_library(systest_static STATIC ${src_files})
set_target_properties(systest_static PROPERTIES
    OUTPUT_NAME "systest_static"
    ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin/")
target_compile_definitions(systest_static PUBLIC SYSTEST_EXPORT SYSTEST_AS_LIBRARY)
