// Copyright (c) 2018, Marco Esposito (marcoesposito1988@gmail.com).
// Please see the AUTHORS file for details. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

import 'dart:convert';
import 'package:convert/convert.dart';
import 'dart:math' as math;
import 'package:crypto/crypto.dart' as crypto;
import 'package:http/http.dart' as http;


Map<String, String> splitAuthenticateHeader(String header) {
  if (header == null || !header.startsWith('Digest ')) {
    return null; // TODO exception?
  }
  header = header.substring(7); // remove 'Digest '

  var ret = new Map<String, String>();

  final components = header.split(', ');
  for (var component in components) {
    final kv = component.split('=');
    ret[kv[0]] = kv.getRange(1, kv.length).join('=').replaceAll('"', '');
  }
  return ret;
}

String md5Hash(String data) {
  var content = new Utf8Encoder().convert(data);
  var md5 = crypto.md5;
  var digest = md5.convert(content).toString();
  return digest;
}

// from http_retry
/// Returns a copy of [original].
http.Request _copyNormalRequest(http.Request original) {
  var request = new http.Request(original.method, original.url);
  request.followRedirects = original.followRedirects;
  request.headers.addAll(original.headers);
  request.maxRedirects = original.maxRedirects;
  request.persistentConnection = original.persistentConnection;
  request.body = original.body;

  return request;
}

http.BaseRequest copyRequest(http.BaseRequest original) {
  if (original is http.Request) {
    return _copyNormalRequest(original);
  } else {
    throw UnimplementedError('cannot handle yet requests of type ${original.runtimeType}');
  }
}

// Digest auth


String _formatNonceCount(int nc) {
  return nc.toRadixString(16).padLeft(8, '0');
}

String _computeHA1(String realm, String algorithm, String username,
    String password, String nonce, String cnonce) {
  var ha1 = null;

  if (algorithm == null || algorithm == 'MD5') {
    final token1 = "$username:$realm:$password";
    ha1 = md5Hash(token1);
  } else if (algorithm == 'MD5-sess') {
    final token1 = "$username:$realm:$password";
    final md51 = md5Hash(token1);
    final token2 = "$md51:$nonce:$cnonce";
    ha1 = md5Hash(token2);
  }

  return ha1;
}

Map<String, String> computeResponse(
    String method,
    String path,
    String body,
    String algorithm,
    String qop,
    String opaque,
    String realm,
    String cnonce,
    String nonce,
    int nc,
    String username,
    String password) {
  var ret = new Map<String, String>();

  final HA1 = _computeHA1(realm, algorithm, username, password, nonce, cnonce);

  var HA2 = null;

  if (qop == 'auth-int') {
    final bodyHash = md5Hash(body);
    final token2 = "$method:$path:$bodyHash";
    HA2 = md5Hash(token2);
  } else {
    // qop in [null, auth]
    final token2 = "$method:$path";
    HA2 = md5Hash(token2);
  }

  final nonceCount = _formatNonceCount(nc);
  ret['username'] = username;
  ret['realm'] = realm;
  ret['nonce'] = nonce;
  ret['uri'] = path;
  ret['qop'] = qop;
  ret['nc'] = nonceCount;
  ret['cnonce'] = cnonce;
  if (opaque != null) {
    ret['opaque'] = opaque;
  }
  ret['algorithm'] = algorithm;

  if (qop == null) {
    final token3 = "$HA1:$nonce:$HA2";
    ret['response'] = md5Hash(token3);
  } else if (qop == 'auth' || qop == 'auth-int') {
    final token3 = "$HA1:$nonce:$nonceCount:$cnonce:$qop:$HA2";
    ret['response'] = md5Hash(token3);
  }

  return ret;
}

class DigestAuth {

  String username;
  String password;

  // must get from first response
  String _algorithm = null;
  String _qop = null;
  String _realm = null;
  String _nonce = null;
  String _opaque = null;

  int _nc = 0; // request counter
  String _cnonce = null; // client-generated; should change for each request

  DigestAuth(this.username, this.password) {}

  String _computeNonce() {
    math.Random rnd = new math.Random();

    List<int> values = new List<int>.generate(16, (i) => rnd.nextInt(256));

    return hex.encode(values);
  }

  String getAuthString(String method, Uri url) {
    _cnonce = _computeNonce();
    _nc += 1;
    // after the first request we have the nonce, so we can provide credentials
    var authValues = computeResponse(method, url.path, '',
        _algorithm, _qop, _opaque, _realm, _cnonce, _nonce, _nc, username, password);
    final authValuesString = authValues.entries
        .where((e) => e.value != null)
        .map((e) => [e.key, '="', e.value, '"'].join(''))
        .toList()
        .join(', ');
    final authString = 'Digest $authValuesString';
    return authString;
  }

  void initFromAuthorizationHeader(String authInfo) {

    Map<String, String> values = splitAuthenticateHeader(authInfo);
    _algorithm = values['algorithm'];
    _qop = values['qop'];
    _realm = values['realm'];
    _nonce = values['nonce'];
    _opaque = values['opaque'];
  }

  bool isReady() {
    return _nonce != null;
  }
}