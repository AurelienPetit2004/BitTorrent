file_include = [ include_directories('include') ]

sources_file = files('src/file_handler.c', 'src/piece.c')

mbtfile = shared_library(
  'mbtfile',
  sources : sources_utils + sources_be + sources_file,
  include_directories : utils_include + be_src_include + be_include + file_include,
  dependencies : dependency('openssl'),
)

mbtfile_dep = declare_dependency(
  include_directories : file_include,
  link_with : mbtfile,
  dependencies : dependency('openssl'),
)
