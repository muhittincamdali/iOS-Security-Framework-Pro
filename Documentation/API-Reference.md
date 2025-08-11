# API Reference

## Core Classes

### Main Framework

The main entry point for the iOS-Security-Framework-Pro framework.

```swift
public class iOS-Security-Framework-Pro {
    public init()
    public func configure()
    public func reset()
}
```

## Configuration

### Options

```swift
public struct Configuration {
    public var debugMode: Bool
    public var logLevel: LogLevel
    public var cacheEnabled: Bool
}
```

## Error Handling

```swift
public enum iOS-Security-Framework-ProError: Error {
    case configurationFailed
    case initializationError
    case runtimeError(String)
}
