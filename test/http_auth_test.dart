// Copyright (c) 2018, Marco Esposito (marcoesposito1988@gmail.com).
// Please see the AUTHORS file for details. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

import 'package:http_auth/http_auth.dart';
import 'package:test/test.dart';
import 'package:http/http.dart' as http;

void main() async {
  group('Basic Auth', () {
    http.BaseClient client;
    String url = 'http://eu.httpbin.org/basic-auth/user/passwd';

//    setUp(() {
//
//    });

    test('One request', () async {
      client = new BasicAuthClient("user", "passwd");

      var response = await client.get(url);
      expect(response.statusCode == 200, isTrue);
    });
  });

  group('Digest Auth', () {
    http.BaseClient client;
    String url = 'http://eu.httpbin.org/digest-auth/auth/user/passwd';

//    setUp(() {
//
//    });

    test('One request', () async {
      client = new DigestAuthClient("user", "passwd");

      var response = await client.get(url);
      expect(response.statusCode == 200, isTrue);
    });

    test('Two requests', () async {
      client = new DigestAuthClient("user", "passwd");

      var response = await client.get(url);
      expect(response.statusCode == 200, isTrue);

      response = await client.get(url);
      expect(response.statusCode == 200, isTrue);
    });
  });
}
