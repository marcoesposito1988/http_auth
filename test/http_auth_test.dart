// Copyright (c) 2018, Marco Esposito (marcoesposito1988@gmail.com).
// Please see the AUTHORS file for details. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

import 'package:http_auth/http_auth.dart';
import 'package:test/test.dart';
import 'package:http/http.dart' as http;

void main() async {
  group('httpbin Basic Auth', () {
    http.BaseClient client;

//    setUp(() {
//
//    });

    test('HTTP', () async {
      String url = 'http://eu.httpbin.org/basic-auth/user/passwd';
      client = new BasicAuthClient("user", "passwd");

      var response = await client.get(url);
      expect(response.statusCode == 200, isTrue);
    });

    test('HTTPS', () async {
      String url = 'https://eu.httpbin.org/basic-auth/user/passwd';
      client = new BasicAuthClient("user", "passwd");

      var response = await client.get(url);
      expect(response.statusCode == 200, isTrue);
    });
  });

  group('httpbin Digest Auth', () {
    http.BaseClient client;

//    setUp(() {
//
//    });

    test('HTTP', () async {
      String url = 'http://eu.httpbin.org/digest-auth/auth/user/passwd';
      client = new DigestAuthClient("user", "passwd");

      var response = await client.get(url);
      expect(response.statusCode == 200, isTrue);
    });

    test('HTTPS', () async {
      String url = 'https://eu.httpbin.org/digest-auth/auth/user/passwd';
      client = new DigestAuthClient("user", "passwd");

      var response = await client.get(url);
      expect(response.statusCode == 200, isTrue);
    });
  });

  group('jigsaw Digest Auth', () {
    http.BaseClient client;

//    setUp(() {
//
//    });

    test('HTTP', () async {
      String url = 'http://jigsaw.w3.org/HTTP/Digest/';
      client = new DigestAuthClient("guest", "guest");

      var response = await client.get(url);
      expect(response.statusCode, 200);
    });

    test('HTTPS', () async {
      String url = 'https://jigsaw.w3.org/HTTP/Digest/';
      client = new DigestAuthClient("guest", "guest");

      var response = await client.get(url);
      expect(response.statusCode, 200);
    });
  });
}
