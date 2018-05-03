// Copyright (c) 2018, Marco Esposito (marcoesposito1988@gmail.com).
// Please see the AUTHORS file for details. All rights reserved.
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file.

import 'package:http_auth/http_auth.dart';

main() {
  var client = new DigestAuthClient("user", "passwd");

  final url = 'http://httpbin.org/digest-auth/auth/user/passwd';

  client.get(url).then((r) => print(r.body));
}
