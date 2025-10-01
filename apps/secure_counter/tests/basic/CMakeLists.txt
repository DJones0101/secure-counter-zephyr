cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(secure_counter_basic_test)

# Reuse the app's main source (two dirs up)
target_sources(app PRIVATE ../../src/main.c)
