import 'package:http/http.dart' as http;
import 'package:http_auth/http_auth.dart';
import 'package:http_auth/src/http_auth_utils.dart';

class NegotiateAuthClient extends http.BaseClient {
  final String _username;
  final String _password;
  final http.Client _inner;
  http.Client _authClient;

  /// Creates a client wrapping [inner] that uses Basic HTTP auth.
  ///
  /// Constructs a new [BasicAuthClient] which will use the provided [username]
  /// and [password] for all subsequent requests.
  NegotiateAuthClient(this._username, this._password, {http.Client inner})
      : _inner = inner ?? http.Client();

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    if (_authClient != null) {
      return await _authClient.send(request);
    }
    final response = await _inner.send(request);

    if (response.statusCode == 401) {
      final authHeader = response.headers[HttpConstants.headerWwwAuthenticate];
      final scheme =
          authHeader.substring(0, authHeader.indexOf(' ')).toLowerCase();
      switch (scheme) {
        case HttpConstants.authSchemeBasic:
          _authClient = BasicAuthClient(_username, _password, inner: _inner);
          break;
        case HttpConstants.authSchemeDigest:
          _authClient = DigestAuthClient(_username, _password,
              inner: _inner, authenticationHeader: authHeader);
          break;
        default:
          throw StateError('Unsupported authenticate scheme $scheme');
      }
      final newRequest = copyRequest(request);

      return await _authClient.send(newRequest);
    }

    return response;
  }
}
