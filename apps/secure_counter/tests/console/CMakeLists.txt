cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(secure_counter_console_test)

# Use an absolute path to the app's main.c (robust in Twister builds)
target_sources(app PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../../src/main.c)
