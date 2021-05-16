A library for Dart developers.

Created from templates made available by Stagehand under a BSD-style
[license](https://github.com/dart-lang/stagehand/blob/master/LICENSE).

## Usage

A simple usage example:

```dart
import 'package:cloud_storage_signer/cloud_storage_signer.dart';

main() {
  var credential = ServiceAccountCredentials.fromJson(json);
  
  var cloudStorageSigner = CloudStorageSigner(
    serviceAccountCredentials: credential,
    serviceAccountEmailOrId: serviceAccountName,
  );

  var url = await cloudStorageSigner.generateSignedUrl(
    httpVerb: HTTPVerb.Get,
    bucketName: 'your-backet',
    filePath: 'file-path',
    region: 'auto',
    from: DateTime.now(),
    expires: Duration(hours: 1),
  );

  print(url);
}
```

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: http://example.com/issues/replaceme
