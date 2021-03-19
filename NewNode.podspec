Pod::Spec.new do |s|
  s.name = 'NewNode'
  s.version = File.read("constants.h").match(/VERSION \"(.*)\"/)[1]
  s.summary = 'NewNode decentralized Content Distribution Network'
  s.homepage = 'http://newnode.com'
  s.license = { :type => 'GPLv2', :file => 'LICENSE' }
  s.author = 'Clostra'
  s.platform = :ios
  s.ios.deployment_target = '9.0'
  s.pod_target_xcconfig = { 'ONLY_ACTIVE_ARCH' => 'YES' }
  s.user_target_xcconfig = { 'ONLY_ACTIVE_ARCH' => 'YES' }
  s.source = { :http => "https://github.com/clostra/newnode/releases/download/#{s.version}/NewNode.framework.zip" }
  s.vendored_frameworks = 'NewNode.framework'
end
