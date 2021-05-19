import 'dart:convert';
import 'package:convert/convert.dart';

import 'package:crypto/crypto.dart';
import 'package:enum_to_string/enum_to_string.dart';
import 'package:googleapis_auth/auth_io.dart' as auth;
import 'package:googleapis_auth/src/crypto/rsa_sign.dart';
import 'package:intl/intl.dart';
import 'package:path/path.dart' as path;

class CloudStorageSigner {
  final auth.ServiceAccountCredentials serviceAccountCredentials;
  final RS256Signer signer;

  CloudStorageSigner({
    required this.serviceAccountCredentials,
  }) : signer = RS256Signer(serviceAccountCredentials.privateRSAKey);

  Future<String> generateSignedUrl({
    required HTTPVerb httpVerb,
    required String bucketName,
    required String filePath,
    required String region,
    required DateTime from,
    required Duration expires,
    Map<String, String>? additionalHeaders,
  }) async {
    var credentialScope = CredentialScope(from, region);
    var header = CanonicalHeaders(additionalHeaders: additionalHeaders);

    var query = CanonicalQuery(
      signingAlgorithm: SigningAlgorithm.RSA,
      authorizer: serviceAccountCredentials.email,
      credentialScope: credentialScope,
      date: from,
      expires: expires,
      canonicalHeaders: header,
    );

    var canonicalRequest = CanonicalRequest(
      httpVerb: httpVerb,
      pathToResource: path.join('/$bucketName', filePath),
      canonicalQuery: query,
      canonicalHeaders: header,
    );

    var signatures = Signatures(
      signingAlgorithm: SigningAlgorithm.RSA,
      activeDateTime: from,
      credentialScope: credentialScope,
      canonicalRequest: canonicalRequest,
    );

    return _generateSignedUrl(
        canonicalRequest: canonicalRequest, signatures: signatures);
  }

  Future<String> _generateSignedUrl({
    required CanonicalRequest canonicalRequest,
    required Signatures signatures,
  }) async {
    var signed = signer.sign(ascii.encode(signatures.stringToSign));

    var signature = hex.encode(signed).toLowerCase();

    var uri = Uri.https(
      canonicalRequest.canonicalHeaders.host,
      canonicalRequest.pathToResource,
      canonicalRequest.canonicalQuery.queryMap
        ..addAll(
          {
            'x-goog-signature': signature,
          },
        ),
    );

    return uri.toString();
  }
}

class CanonicalRequest {
  final HTTPVerb httpVerb;
  final String pathToResource;
  final CanonicalQuery canonicalQuery;
  final CanonicalHeaders canonicalHeaders;
  final String? payload;

  CanonicalRequest({
    required this.httpVerb,
    required this.pathToResource,
    required this.canonicalQuery,
    required this.canonicalHeaders,
    this.payload,
  });

  String get canonicalRequestString {
    return [
      '${EnumToString.convertToString(httpVerb).toUpperCase()}',
      '$pathToResource',
      '${canonicalQuery.queryString}',
      '${canonicalHeaders.canonicalHeadersString}',
      '',
      '${canonicalHeaders.signedHeadersString}',
      '${payload ?? 'UNSIGNED-PAYLOAD'}',
    ].join('\n');
  }

  String get hashedRequestString {
    var bytes = ascii.encode(canonicalRequestString);
    var digest = sha256.convert(bytes);

    var digestHex = digest.toString();

    return digestHex;
  }
}

final DateFormat iso8601DateFormat = DateFormat('yyyyMMdd\'T\'HHmmss\'Z\'');

class CanonicalQuery {
  final String signingAlgorithm;
  final String authorizer;
  final CredentialScope credentialScope;
  final DateTime date;
  final Duration expires;
  final CanonicalHeaders canonicalHeaders;
  final Map<String, String>? additionalHeaders;

  CanonicalQuery({
    required this.signingAlgorithm,
    required this.authorizer,
    required this.credentialScope,
    required this.date,
    required this.expires,
    required this.canonicalHeaders,
    this.additionalHeaders,
  });

  Map<String, String> get queryMap {
    var map = <String, String>{
      'x-goog-algorithm': signingAlgorithm,
      'x-goog-credential':
          '$authorizer/${credentialScope.credentialScopeString}',
      'x-goog-date': iso8601DateFormat.format(date.toUtc()),
      'x-goog-expires': expires.inSeconds.toString(),
      'x-goog-signedheaders': canonicalHeaders.signedHeadersString,
    };

    if (additionalHeaders != null) {
      map.addAll(additionalHeaders!);
    }

    return map;
  }

  String get queryString {
    var list = queryMap.entries
        .map((e) =>
            '${e.key.toLowerCase()}=${Uri.encodeQueryComponent(e.value)}')
        .toList();
    list.sort();
    return list.join('&');
  }
}

class CanonicalHeaders {
  final String host = 'storage.googleapis.com';
  final Map<String, String>? additionalHeaders;

  CanonicalHeaders({this.additionalHeaders});

  Map<String, String> get headers {
    var headerMap = {
      'host': host,
    };

    if (additionalHeaders != null) {
      headerMap.addAll(additionalHeaders!);
    }

    return headerMap;
  }

  String get canonicalHeadersString {
    var list = headers.entries
        .map((e) => '${e.key.toLowerCase()}:${e.value}')
        .toSet()
        .toList();
    list.sort();
    return list.join('\n');
  }

  String get signedHeadersString {
    var list = headers.keys.toSet().map((e) => e.toLowerCase()).toList();
    list.sort();
    return list.join(';');
  }
}

class Signatures {
  final String signingAlgorithm;
  final DateTime activeDateTime;
  final CredentialScope credentialScope;
  final CanonicalRequest canonicalRequest;

  Signatures({
    required this.signingAlgorithm,
    required this.activeDateTime,
    required this.credentialScope,
    required this.canonicalRequest,
  });

  String get stringToSign {
    return [
      '$signingAlgorithm',
      '${iso8601DateFormat.format(activeDateTime.toUtc())}',
      '${credentialScope.credentialScopeString}',
      '${canonicalRequest.hashedRequestString}',
    ].join('\n');
  }
}

class CredentialScope {
  final DateTime date;
  final String location;
  final String service = 'storage';
  final String requestType = 'goog4_request';

  CredentialScope(this.date, this.location);

  final DateFormat dateFormat = DateFormat('yyyyMMdd');

  String get credentialScopeString {
    return '${dateFormat.format(date.toUtc())}/$location/$service/$requestType';
  }
}

enum HTTPVerb {
  Delete,
  Get,
  Head,
  Post,
  Put,
}

class SigningAlgorithm {
  /// 'GOOG4-RSA-SHA256'
  static const String RSA = 'GOOG4-RSA-SHA256';

  /// 'GOOG4-HMAC-SHA256'
  static const String HMAC = 'GOOG4-HMAC-SHA256';
}
