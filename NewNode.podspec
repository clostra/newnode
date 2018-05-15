Pod::Spec.new do |s|
  s.name = 'NewNode'
  s.version = File.read("constants.h").match(/VERSION \"(.*)\"/)[1]
  s.summary = 'NewNode decentralized Content Distribution Network'
  s.homepage = 'http://newnode.com'
  s.license = { :type => 'GPLv2', :file => 'LICENSE' }
  s.author = 'Clostra'
  s.platform = :ios
  s.source = { :http => "https://github.com/clostra/newnode/releases/download/#{s.version}/newnode.ios.zip" }
  s.vendored_frameworks = 'NewNode.framework'
end
