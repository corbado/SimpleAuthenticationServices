// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "SimpleAuthenticationServices",   
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "SimpleAuthenticationServices",
            targets: ["SimpleAuthenticationServices"]),
        .library(
            name: "SimpleAuthenticationServicesMocks",
            targets: ["SimpleAuthenticationServicesMocks"]),
    ],
    dependencies: [
        .package(url: "https://github.com/SomeRandomiOSDev/CBORCoding.git", from: "1.4.0"),
        .package(url: "https://github.com/httpswift/swifter.git", .upToNextMajor(from: "1.5.0")),
    ],
    targets: [
        .target(
            name: "SimpleAuthenticationServices",
            dependencies: [],
            path: "Sources",
            exclude: ["Virtual"], 
            sources: ["Real", "SimpleAuthenticationServices.swift"]
        ),
        .target(
            name: "SimpleAuthenticationServicesMocks",
            dependencies: [
                "SimpleAuthenticationServices",
                .product(name: "CBORCoding", package: "CBORCoding"),
                .product(name: "Swifter", package: "swifter"),
            ],
            path: "Sources/Virtual" 
        ),
        .testTarget(
            name: "SimpleAuthenticationServicesTests",
            dependencies: [
                "SimpleAuthenticationServicesMocks"
            ],
            resources: [
                .copy("TestBinaries")
            ]
        ),
    ]
)
