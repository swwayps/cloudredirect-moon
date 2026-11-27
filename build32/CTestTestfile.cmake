# CMake generated Testfile for 
# Source directory: /build
# Build directory: /build/build32
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[cli_packaging_test]=] "bash" "/build/test/cli_packaging_test.sh")
set_tests_properties([=[cli_packaging_test]=] PROPERTIES  _BACKTRACE_TRIPLES "/build/CMakeLists.txt;241;add_test;/build/CMakeLists.txt;0;")
add_test([=[cli_folder_provider_test]=] "bash" "/build/test/cli_folder_provider_test.sh" "/build/build32/cloud_redirect_cli32")
set_tests_properties([=[cli_folder_provider_test]=] PROPERTIES  _BACKTRACE_TRIPLES "/build/CMakeLists.txt;243;add_test;/build/CMakeLists.txt;0;")
add_test([=[provider_config_tests]=] "/build/build32/provider_config_tests")
set_tests_properties([=[provider_config_tests]=] PROPERTIES  _BACKTRACE_TRIPLES "/build/CMakeLists.txt;254;add_test;/build/CMakeLists.txt;0;")
add_test([=[linux_stats_scope_tests]=] "/build/build32/linux_stats_scope_tests")
set_tests_properties([=[linux_stats_scope_tests]=] PROPERTIES  _BACKTRACE_TRIPLES "/build/CMakeLists.txt;265;add_test;/build/CMakeLists.txt;0;")
add_test([=[linux_stats_no_bridge_tests]=] "/build/build32/linux_stats_no_bridge_tests")
set_tests_properties([=[linux_stats_no_bridge_tests]=] PROPERTIES  _BACKTRACE_TRIPLES "/build/CMakeLists.txt;265;add_test;/build/CMakeLists.txt;0;")
add_test([=[linux_stats_archive_tests]=] "/build/build32/linux_stats_archive_tests")
set_tests_properties([=[linux_stats_archive_tests]=] PROPERTIES  _BACKTRACE_TRIPLES "/build/CMakeLists.txt;274;add_test;/build/CMakeLists.txt;0;")
add_test([=[linux_lua_discovery_tests]=] "/build/build32/linux_lua_discovery_tests")
set_tests_properties([=[linux_lua_discovery_tests]=] PROPERTIES  _BACKTRACE_TRIPLES "/build/CMakeLists.txt;279;add_test;/build/CMakeLists.txt;0;")
add_test([=[linux_init_stop_tests]=] "/build/build32/linux_init_stop_tests")
set_tests_properties([=[linux_init_stop_tests]=] PROPERTIES  _BACKTRACE_TRIPLES "/build/CMakeLists.txt;286;add_test;/build/CMakeLists.txt;0;")
add_test([=[linux_late_discovery_queue_tests]=] "/build/build32/linux_late_discovery_queue_tests")
set_tests_properties([=[linux_late_discovery_queue_tests]=] PROPERTIES  _BACKTRACE_TRIPLES "/build/CMakeLists.txt;293;add_test;/build/CMakeLists.txt;0;")
