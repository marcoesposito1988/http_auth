// Copyright (c) 2018, Marco Esposito (marcoesposito1988@gmail.com).
// Please see the AUTHORS file for details. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

import 'dart:async';

import 'package:http/http.dart' as http;

import 'http_auth_utils.dart' as utils;

/// Http client holding a username and password to be used for Digest authentication
class DigestAuthClient extends http.BaseClient {
  final http.Client _inner;

  final utils.DigestAuth _auth;

  /// Creates a client wrapping [inner] that uses Basic HTTP auth.
  ///
  /// Constructs a new [BasicAuthClient] which will use the provided [username]
  /// and [password] for all subsequent requests.
  DigestAuthClient(String username, String password,
      {http.Client inner, String authenticationHeader})
      : _auth = utils.DigestAuth(username, password),
        _inner = inner ?? http.Client() {
    if (authenticationHeader != null) {
      _auth.initFromAuthorizationHeader(authenticationHeader);
    }
  }

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    if (_auth.isReady()) {
      request.headers[utils.HttpConstants.headerAuthorization] =
          _auth.getAuthString(request.method, request.url);
    }
    final response = await _inner.send(request);

    if (response.statusCode == 401) {
      final newRequest = utils.copyRequest(request);
      final authInfo =
          response.headers[utils.HttpConstants.headerWwwAuthenticate];
      _auth.initFromAuthorizationHeader(authInfo);

      newRequest.headers[utils.HttpConstants.headerAuthorization] =
          _auth.getAuthString(newRequest.method, newRequest.url);

      return _inner.send(newRequest);
    }

    // we should reach this point only with errors other than 401
    return response;
  }

  @override
  void close() {
    _inner.close();
  }
}
