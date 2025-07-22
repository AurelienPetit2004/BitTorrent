be_include = [ include_directories('include') ]

sources_be = files('src/get.c', 'src/be.c', 'src/decode.c', 'src/encode.c', 'src/node.c')

ssl = dependency('openssl')

be_src_include = [ include_directories('src') ]

mbtbe = shared_library(
  'mbtbe',
  sources : sources_be + sources_utils,
  include_directories : utils_include + be_include + be_src_include,
  dependencies : [ ssl ],
)

mbtbe_dep = declare_dependency(
  include_directories : be_include,
  dependencies : [ ssl ],
  link_with : mbtbe,
)
