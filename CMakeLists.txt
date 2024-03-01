cmake_minimum_required(VERSION 3.5.0)
project(L2C VERSION 0.0.1 LANGUAGES C)

add_executable(L2C main.c)

target_link_libraries(L2C pthread)