[![pub package](https://img.shields.io/pub/v/http_auth.svg)](https://pub.dartlang.org/packages/http_auth)

# http_auth

An [`http`](https://pub.dartlang.org/packages/http) middleware for HTTP authentication (Basic/Digest).

## Usage

HTTP Basic authentication:

```dart
    import 'package:http_auth/http_auth.dart';

    main() async {
      var client = http_auth.BasicAuthClient('user', 'passwd');
      var response = client.get('http://httpbin.org/basic-auth/user/passwd');
    }
```

HTTP Digest authentication:

```dart
    import 'package:http_auth/http_auth.dart';

    main() async {
      var client = http_auth.DigestAuthClient('user', 'passwd');
      var response = client.get('http://httpbin.org/digest-auth/auth/user/passwd');
    }
```

Synchronous usage is also possible (see the [example](example/http_auth_example.dart)).

