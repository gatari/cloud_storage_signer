import 'dart:convert';
import 'dart:io';

import 'package:cloud_storage_signer/cloud_storage_signer.dart';
import 'package:googleapis_auth/auth_io.dart';
import 'package:test/test.dart';

void main() async {
  var credentialString = await File('credentials.json').readAsString();
  var json = jsonDecode(credentialString);
  var credential = ServiceAccountCredentials.fromJson(json);

  group('canonical request', () {
    test('generate post url', () async {
      var cloudStorageSigner = CloudStorageSigner(
        serviceAccountCredentials: credential,
      );

      var url = await cloudStorageSigner.generateSignedUrl(
        bucketName: Platform.environment['BUCKET_NAME']!,
        filePath: Platform.environment['FILE_PATH']!,
        region: 'auto',
        expires: Duration(hours: 1),
        from: DateTime.now(),
        httpVerb: HTTPVerb.Get,
      );

      print(url);
    });
  });
}
