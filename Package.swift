// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "CapacitorSecureBiometricCredentialPlugin",
    platforms: [.iOS(.v14)],
    products: [
        .library(
            name: "CapacitorSecureBiometricCredentialPlugin",
            targets: ["BiometricCredentialPlugin"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/ionic-team/capacitor-swift-pm.git", from: "8.0.0")
    ],
    targets: [
        .target(
            name: "BiometricCredentialPlugin",
            dependencies: [
                .product(name: "Capacitor", package: "capacitor-swift-pm")
            ],
            path: "ios/Plugin"
        )
    ]
)
