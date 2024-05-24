import 'dart:convert';
import 'dart:io';

import 'package:dart_frog/dart_frog.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:dotenv/dotenv.dart';
import 'package:github/github.dart';
import 'package:google_generative_ai/google_generative_ai.dart';
import 'package:http/http.dart' as http;

Future<String?> accessToken(
  int installationId,
  String base64Pem,
  String githubAppId,
) async {
  final pem = utf8.decode(base64Decode(base64Pem));
  File('./github.pem').writeAsStringSync(pem);

  final privateKeyString = File('./github.pem').readAsStringSync();
  final privateKey = RSAPrivateKey(privateKeyString);

  final jwt = JWT(
    {
      'iat': DateTime.now().millisecondsSinceEpoch ~/ 1000,
      'exp': DateTime.now()
              .add(const Duration(minutes: 10))
              .millisecondsSinceEpoch ~/
          1000,
      'iss': int.parse(githubAppId),
    },
  );

  final token = jwt.sign(privateKey, algorithm: JWTAlgorithm.RS256);

  final response = await http.post(
    Uri.parse(
      'https://api.github.com/app/installations/$installationId/access_tokens',
    ),
    headers: {
      HttpHeaders.authorizationHeader: 'Bearer $token',
      HttpHeaders.acceptHeader: 'application/vnd.github.v3+json',
    },
  );

  final responseBody = jsonDecode(response.body) as Map<String, dynamic>;

  if (response.statusCode == 201) {
    return responseBody['token'].toString();
  } else {
    return null;
  }
}

Future<Response> onRequest(RequestContext context) async {
  final env = DotEnv(includePlatformEnvironment: true)..load();

  final base64Pem = env['PEM_BASE64'];

  if (base64Pem == null) {
    throw Exception('base64Pem is null');
  }

  final githubAppId = env['GITHUB_APP_ID'];
  if (githubAppId == null) {
    throw Exception('githubAppId is null');
  }

  final geminiApiKey = env['GEMINI_API_KEY'];

  if (geminiApiKey == null) {
    throw Exception('geminiApiKey is null');
  }

  final body = await context.request.body();
  final json = jsonDecode(body) as Map<String, dynamic>;
  final installationId = json['installation']['id'] as int;

  final token = await accessToken(
    installationId,
    base64Pem,
    githubAppId,
  );

  if (token == null) {
    throw Exception('Failed to obtain GitHub access token');
  }

  final github = GitHub(auth: Authentication.withToken(token));

  final action = json['action'];
  final fullName = json['repository']['full_name'] as String;
  final pullRequest = json['pull_request'] as Map<String, dynamic>?;

  if ((action == 'opened' || action == 'reopened') && pullRequest != null) {
    final issueNumber = pullRequest['number'] as int?;

    if (issueNumber == null) {
      throw Exception('prNumber is null');
    }

    final diffApiUrl =
        'https://api.github.com/repos/$fullName/pulls/$issueNumber/files';
    final diffResponse = await http.get(
      Uri.parse(diffApiUrl),
      headers: {
        'Authorization': 'token $token',
        'Accept': 'application/vnd.github.v3+json',
      },
    );

    if (diffResponse.statusCode == 200) {
      final files = jsonDecode(diffResponse.body) as List<dynamic>;

      for (final file in files) {
        final filename = file['filename'];
        final status = file['status'];
        final additions = file['additions'];
        final deletions = file['deletions'];
        final changes = file['changes'];
        final patch = file['patch'];

        final diffInfo = {
          'filename': filename,
          'status': status,
          'additions': additions,
          'deletions': deletions,
          'changes': changes,
          'patch': patch,
        };

        final model = GenerativeModel(
          model: 'gemini-1.5-flash-latest',
          apiKey: geminiApiKey,
        );

        final prompt = '次のコードを日本語でレビューして: $diffInfo';
        final content = [Content.text(prompt)];
        final response = await model.generateContent(content);

        final comments = <PullRequestReviewComment>[
          PullRequestReviewComment(
            path: diffInfo['filename'].toString(),
            position: 1,
            body: response.text,
          ),
        ];

        final owner = fullName.split('/')[0];
        final repo = fullName.split('/')[1];

        final review = CreatePullRequestReview(
          owner,
          repo,
          issueNumber,
          'COMMENT',
          comments: comments,
        );

        await github.pullRequests.createReview(
          RepositorySlug(owner, repo),
          review,
        );
      }
    } else {
      print('Failed to load PR diff: ${diffResponse.statusCode}');
    }
  }

  return Response(body: 'Success');
}
