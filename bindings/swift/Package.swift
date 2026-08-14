// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "UMC",
    products: [.library(name: "UMC", targets: ["UMC"])],
    targets: [
        .target(name: "UMC"),
        .testTarget(name: "UMCTests", dependencies: ["UMC"]),
    ]
)
