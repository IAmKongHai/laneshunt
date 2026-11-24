// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "LaneShunt",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
    ],
    products: [
        .library(
            name: "LaneShunt",
            targets: ["LaneShunt"]
        ),
    ],
    targets: [
        .target(
            name: "LaneShunt",
            path: "swift/Sources/LaneShunt"
        ),
        .testTarget(
            name: "LaneShuntTests",
            dependencies: ["LaneShunt"],
            path: "swift/Tests/LaneShuntTests"
        ),
    ],
    swiftLanguageModes: [.v5]
)
