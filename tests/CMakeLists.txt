add_executable(voipscope_tests
    test_sip_parser.cpp
    test_dialog_fsm.cpp
    test_jitter.cpp
    test_mos.cpp
    test_cdr.cpp
    test_integration.cpp
)

target_link_libraries(voipscope_tests
    PRIVATE
        voipscope_lib
        GTest::gtest_main
)

target_compile_definitions(voipscope_tests PRIVATE
    FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
)

include(GoogleTest)
gtest_discover_tests(voipscope_tests)
