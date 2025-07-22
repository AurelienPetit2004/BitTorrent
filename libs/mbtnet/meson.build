net_include = [ include_directories('include') ]

sources_net = files('src/context.c') 

mbtnet = shared_library(
  'mbtnet',
  sources : sources_net,
  include_directories : net_include,
)

mbtnet_dep = declare_dependency(
  include_directories : net_include,
  link_with : mbtnet,
)
