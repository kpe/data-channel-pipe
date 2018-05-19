# Walk through subdirectories
add_subdirectory(helper)

# rawrtc-terminal
add_executable(rawrtc-datachannel-pipe
        rawrtc-datachannel-pipe.c)
target_link_libraries(rawrtc-datachannel-pipe
        ${dc_pipe_DEP_LIBRARIES}
        rawrtc-helper)
install(TARGETS rawrtc-datachannel-pipe
        DESTINATION bin)
