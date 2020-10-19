// Copyright (c) 2018, Marco Esposito (marcoesposito1988@gmail.com).
// Please see the AUTHORS file for details. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

import 'package:http/http.dart' as http;
import 'package:http_auth/http_auth.dart';
import 'package:http_auth/src/http_auth_negotiate.dart';
import 'package:http_auth/src/http_auth_utils.dart';
import 'package:test/test.dart';

void main() async {
  group('Basic Auth', () {
    http.BaseClient client;

//    setUp(() {
//
//    });

    test('httpbin HTTP', () async {
      final url = 'http://eu.httpbin.org/basic-auth/user/passwd';
      client = BasicAuthClient('user', 'passwd');

      var response = await client.get(url);
      expect(response.statusCode == 200, isTrue);
    });

    test('httpbin HTTPS', () async {
      final url = 'https://eu.httpbin.org/basic-auth/user/passwd';
      client = BasicAuthClient('user', 'passwd');

      var response = await client.get(url);
      expect(response.statusCode == 200, isTrue);
    });

    test('jigsaw HTTP', () async {
      final url = 'http://jigsaw.w3.org/HTTP/Basic/';
      client = BasicAuthClient('guest', 'guest');

      var response = await client.get(url);
      expect(response.statusCode, 200);
    });

    test('jigsaw HTTPS', () async {
      final url = 'https://jigsaw.w3.org/HTTP/Basic/';
      client = BasicAuthClient('guest', 'guest');

      var response = await client.get(url);
      expect(response.statusCode, 200);
    });
  });

  group('Digest Auth', () {
    http.BaseClient client;

//    setUp(() {
//
//    });

    test('httpbin HTTP', () async {
      final url = 'http://eu.httpbin.org/digest-auth/auth/user/passwd';
      client = DigestAuthClient('user', 'passwd');

      var response = await client.get(url);
      expect(response.statusCode == 200, isTrue);
    });

    test('httpbin HTTPS', () async {
      final url = 'https://eu.httpbin.org/digest-auth/auth/user/passwd';
      client = DigestAuthClient('user', 'passwd');

      var response = await client.get(url);
      expect(response.statusCode == 200, isTrue);
    });

    test('jigsaw HTTP', () async {
      final url = 'http://jigsaw.w3.org/HTTP/Digest/';
      client = DigestAuthClient('guest', 'guest');

      var response = await client.get(url);
      expect(response.statusCode, 200);
    });

    test('jigsaw HTTPS', () async {
      final url = 'https://jigsaw.w3.org/HTTP/Digest/';
      client = DigestAuthClient('guest', 'guest');

      var response = await client.get(url);
      expect(response.statusCode, 200);
    });
  });

  group('Automatic negotiation', () {
//    setUp(() {
//
//    });

    test('httpbin HTTPS Basic', () async {
      final url = 'https://eu.httpbin.org/basic-auth/user/passwd';
      final client = NegotiateAuthClient('user', 'passwd');
      final response = await client.get(url);
      expect(response.statusCode, 200);
    });

    test('httpbin HTTPS Digest', () async {
      final url = 'https://eu.httpbin.org/digest-auth/auth/user/passwd';
      final client = NegotiateAuthClient('user', 'passwd');
      final response = await client.get(url);
      expect(response.statusCode, 200);
    });

    test('jigsaw HTTP Basic', () async {
      final url = 'http://jigsaw.w3.org/HTTP/Basic/';
      final client = NegotiateAuthClient('guest', 'guest');
      final response = await client.get(url);
      expect(response.statusCode, 200);
    });

    test('jigsaw HTTP Digest', () async {
      final url = 'http://jigsaw.w3.org/HTTP/Digest/';
      final client = NegotiateAuthClient('guest', 'guest');
      final response = await client.get(url + rand);
      expect(response.statusCode, 200);
    });
  });

  group('Automatic negotiation, multiple requests', () {
//    setUp(() {
//
//    });

    test('httpbin HTTP Digest', () async {
      final url = 'http://httpbin.org/digest-auth/auth/foo/bar';
      final count = _CountingHttpClient();
      final client = NegotiateAuthClient('foo', 'bar', inner: count);
      final response = await client.get(url);
      expect(response.statusCode, 200);
      expect(count.requestCount, 2);
      // lets try a second request.
      final response2 = await client.get(url);
      expect(response2.statusCode, 200);
      expect(count.requestCount, 3);
    });
  });

  group('Automatic negotiation, scheme picking', () {
    test('Basic', () {
      expect(pickSchemeFromAuthenticateHeader('Basic'),
          AuthenticationScheme.Basic);
      expect(pickSchemeFromAuthenticateHeader('Basic,Basic'),
          AuthenticationScheme.Basic);
      expect(pickSchemeFromAuthenticateHeader('basic'),
          AuthenticationScheme.Basic);
      expect(pickSchemeFromAuthenticateHeader('basic,Basic'),
          AuthenticationScheme.Basic);
      expect(pickSchemeFromAuthenticateHeader('Basic,somenoise'),
          AuthenticationScheme.Basic);
      expect(pickSchemeFromAuthenticateHeader('Basic,somenoise=randomstuff'),
          AuthenticationScheme.Basic);
      expect(pickSchemeFromAuthenticateHeader('Basic,,somenoise=randomstuff'),
          AuthenticationScheme.Basic);
      expect(pickSchemeFromAuthenticateHeader('Basic somenoise=randomstuff'),
          AuthenticationScheme.Basic);
      expect(pickSchemeFromAuthenticateHeader('somenoise=randomstuff,Basic'),
          AuthenticationScheme.Basic);
      expect(pickSchemeFromAuthenticateHeader('somenoise=randomstuff,,Basic'),
          AuthenticationScheme.Basic);
      expect(pickSchemeFromAuthenticateHeader('somenoise=randomstuff, ,Basic'),
          AuthenticationScheme.Basic);
      expect(pickSchemeFromAuthenticateHeader('somenoise=randomstuff Basic'),
          AuthenticationScheme.Basic);
      expect(pickSchemeFromAuthenticateHeader('negotiate,basic'),
          AuthenticationScheme.Basic);
      expect(
          pickSchemeFromAuthenticateHeader(
              'Negotiate,Basic realm="Keepass DAV data"'),
          AuthenticationScheme.Basic);
    });

    test('Digest', () {
      expect(pickSchemeFromAuthenticateHeader('Digest'),
          AuthenticationScheme.Digest);
      expect(pickSchemeFromAuthenticateHeader('Digest,somenoise'),
          AuthenticationScheme.Digest);
      expect(pickSchemeFromAuthenticateHeader('Digest,somenoise=randomstuff'),
          AuthenticationScheme.Digest);
      expect(pickSchemeFromAuthenticateHeader('Digest,,somenoise=randomstuff'),
          AuthenticationScheme.Digest);
      expect(pickSchemeFromAuthenticateHeader('Digest somenoise=randomstuff'),
          AuthenticationScheme.Digest);
      expect(pickSchemeFromAuthenticateHeader('negotiate,digest'),
          AuthenticationScheme.Digest);
    });

    test('Digest over Basic', () {
      expect(pickSchemeFromAuthenticateHeader('Digest,Basic'),
          AuthenticationScheme.Digest);
      expect(pickSchemeFromAuthenticateHeader('Basic,Digest'),
          AuthenticationScheme.Digest);
      expect(pickSchemeFromAuthenticateHeader('Digest,somenoise'),
          AuthenticationScheme.Digest);
      expect(pickSchemeFromAuthenticateHeader('Digest,somenoise=randomstuff'),
          AuthenticationScheme.Digest);
      expect(pickSchemeFromAuthenticateHeader('Digest,,somenoise=randomstuff'),
          AuthenticationScheme.Digest);
      expect(pickSchemeFromAuthenticateHeader('Digest somenoise=randomstuff'),
          AuthenticationScheme.Digest);
      expect(pickSchemeFromAuthenticateHeader('Digest,somenoise,Basic'),
          AuthenticationScheme.Digest);
      expect(
          pickSchemeFromAuthenticateHeader(
              'Digest,somenoise=randomstuff,Basic'),
          AuthenticationScheme.Digest);
      expect(
          pickSchemeFromAuthenticateHeader(
              'Digest,,somenoise=randomstuff,Basic'),
          AuthenticationScheme.Digest);
      expect(
          pickSchemeFromAuthenticateHeader(
              'Digest somenoise=randomstuff,,Basic'),
          AuthenticationScheme.Digest);
    });

    test('None', () {
      expect(pickSchemeFromAuthenticateHeader('Something'), null);
      expect(pickSchemeFromAuthenticateHeader('Something,somenoise'), null);
      expect(
          pickSchemeFromAuthenticateHeader('Something,somenoise=randomstuff'),
          null);
      expect(
          pickSchemeFromAuthenticateHeader('Something,,somenoise=randomstuff'),
          null);
      expect(
          pickSchemeFromAuthenticateHeader('Something somenoise=randomstuff'),
          null);
    });
  });
}

String get rand => '?t=${DateTime.now().millisecondsSinceEpoch}';

class _CountingHttpClient extends http.BaseClient {
  final _inner = http.Client();
  int requestCount = 0;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    requestCount++;
    return _inner.send(request);
  }
}
