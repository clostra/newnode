// swift-tools-version:5.3
import PackageDescription
let package = Package(
    name: "MyFramework",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(
            name: "NewNode", 
            targets: ["NewNode"])
    ],
    targets: [
        .binaryTarget(
            name: "NewNode", 
            path: "NewNode.xcframework")
    ]
)
