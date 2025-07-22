utils_include = [ include_directories('include') ]

sources_utils = files('src/str.c') 

mbtutils = shared_library(
  'mbtutils',
  sources : sources_utils,
  include_directories : utils_include,
)

mbtutils_dep = declare_dependency(
  include_directories : utils_include,
  link_with : mbtutils,
)
