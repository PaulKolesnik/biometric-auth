Pod::Spec.new do |s|
  s.name = 'CapacitorSecureBiometricCredentialPlugin'
  s.version = '0.1.0'
  s.summary = 'Capacitor secure biometric credential plugin'
  s.license = 'MIT'
  s.homepage = 'https://example.com'
  s.author = 'Biometric Auth Team'
  s.source = { :git => 'https://example.com/repo.git', :tag => s.version.to_s }
  s.source_files = 'ios/Plugin/**/*.{swift,h,m,c,cc,mm,cpp}'
  s.ios.deployment_target = '14.0'
  s.dependency 'Capacitor'
  s.swift_version = '5.9'
end
