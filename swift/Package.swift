// swift-tools-version:5.7

import PackageDescription

let package = Package(
    name: "LicenseCM",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
        .tvOS(.v13),
        .watchOS(.v6)
    ],
    products: [
        .library(
            name: "LicenseCM",
            targets: ["LicenseCM"]),
    ],
    targets: [
        .target(
            name: "LicenseCM",
            dependencies: [],
            path: "Sources/LicenseCM"),
        .testTarget(
            name: "LicenseCMTests",
            dependencies: ["LicenseCM"],
            path: "Tests/LicenseCMTests"),
    ]
)
