Pod::Spec.new do |s|
  s.name = "NewNode"
  s.version = "1.4.1"
  s.summary = "NewNode decentralized Content Distribution Network"
  s.homepage = "http://newnode.com"
  s.license = { :type => "GPLv2", :file => "LICENSE" }
  s.author = 'Clostra'
  s.platform = :ios
  s.source = { :http => "https://github.com/clostra/newnode/releases/download/1.4.1/newnode.ios.zip" }
  s.source_files = 'newnode.h'
  s.vendored_libraries = 'libnewnode.a'
end
