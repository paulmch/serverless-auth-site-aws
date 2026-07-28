import * as cdk from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';
import * as triggers from "aws-cdk-lib/triggers";
import { Construct } from 'constructs';
import { execFileSync } from 'child_process';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

const FRONTEND_DIR = path.join(__dirname, '../frontend/src');

/**
 * Read index.html and inject its Content-Security-Policy as a meta tag.
 *
 * The policy is delivered in the markup rather than as an API Gateway response
 * header because CSP keywords are single-quoted (`'self'`), and API Gateway's
 * static response parameter values are themselves delimited by single quotes
 * with no documented escape. `frame-ancestors` is the one directive a meta tag
 * cannot carry, so framing is denied by the `X-Frame-Options: DENY` header the
 * integration response sets instead.
 *
 * index.html needs one inline script - it sets `<base href>` before the
 * stylesheet link is parsed, so it cannot move to an external file. Rather than
 * weakening the policy with 'unsafe-inline', its SHA-256 is computed here at
 * synth time and whitelisted by hash, so editing that script updates the policy
 * automatically instead of silently breaking the page.
 */
function indexHtmlWithCsp(): string {
  const html = fs.readFileSync(path.join(FRONTEND_DIR, 'index.html'), 'utf8');

  // The single inline <script> block - i.e. the one without a src attribute.
  const inlineScripts = [...html.matchAll(/<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/gi)];
  if (inlineScripts.length !== 1) {
    throw new Error(
      `Expected exactly 1 inline script in index.html, found ${inlineScripts.length}. ` +
      'Update indexHtmlWithCsp() to hash each of them.',
    );
  }

  const digest = createHash('sha256').update(inlineScripts[0][1], 'utf8').digest('base64');

  const policy = [
    "default-src 'none'",
    `script-src 'self' 'sha256-${digest}'`,
    "style-src 'self'",
    "connect-src 'self'",
    "img-src 'self' data:",
    "base-uri 'self'",
    "form-action 'none'",
  ].join('; ');

  const meta = `<meta http-equiv="Content-Security-Policy" content="${policy}">`;

  // Injected after the charset declaration, which must stay first, and before
  // the inline script, which the policy has to cover.
  const charsetMeta = /<meta\s+charset=["'][^"']*["']\s*\/?>/i;
  if (!charsetMeta.test(html)) {
    throw new Error('index.html has no <meta charset> to anchor the CSP injection to.');
  }

  return html.replace(charsetMeta, (match) => `${match}\n    ${meta}`);
}

/**
 * Python runtime for all Lambda functions.
 *
 * Kept on a single constant so the whole stack moves together. Runs on Amazon
 * Linux 2023 - the python3.11 runtime is built on Amazon Linux 2, which reached
 * end of life on 2026-06-30.
 */
const PYTHON_RUNTIME = lambda.Runtime.PYTHON_3_13;

/** Wheel tags matching PYTHON_RUNTIME, used when bundling the layer locally. */
const LAMBDA_PYTHON_VERSION = '3.13';
const LAMBDA_WHEEL_PLATFORM = 'manylinux2014_x86_64';

/**
 * Sustained request rate and burst allowance for the unauthenticated auth
 * endpoints (/auth/callback and /auth/decider).
 */
const PUBLIC_ENDPOINT_RATE_LIMIT = 1;
const PUBLIC_ENDPOINT_BURST_LIMIT = 2;

/**
 * Secure Static Site Stack
 *
 * Creates a fully secured static website infrastructure with:
 * - Cognito authentication with hosted UI
 * - API Gateway with Lambda authorizer for access control
 * - S3 bucket for static file storage (served through API Gateway)
 * - DynamoDB for user session management
 * - Rate-limited public endpoints
 *
 * All static files are served through API Gateway with authentication,
 * ensuring no public access to the S3 bucket. The stack automatically
 * configures Cognito callback URLs and API Gateway responses.
 */
export class SecureStaticSiteStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Get account ID dynamically
    const accountId = cdk.Stack.of(this).account;

    // ===========================
    // COGNITO USER POOL & HOSTED UI
    // ===========================

    /**
     * Cognito User Pool for authentication
     * - Admin-only registration (self-signup disabled)
     * - Email-based sign-in
     * - Strong password requirements
     * - Email verification enabled
     */
    const userPool = new cognito.UserPool(this, 'StaticSiteUserPool', {
      userPoolName: 'static-site-users',
      selfSignUpEnabled: false, // Admin-only registration
      signInAliases: {
        email: true,
      },
      autoVerify: {
        email: true,
      },
      passwordPolicy: {
        minLength: 12,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    /**
     * Cognito User Pool Client for OAuth2 flow
     * - Authorization code grant flow
     * - OpenID Connect scopes
     * - Placeholder callback URLs (updated by custom resource)
     */
    const userPoolClient = new cognito.UserPoolClient(this, 'StaticSiteUserPoolClient', {
      userPool,
      userPoolClientName: 'static-site-client',
      generateSecret: false,
      authFlows: {
        userPassword: true,
        userSrp: true,
      },
      oAuth: {
        flows: {
          authorizationCodeGrant: true,
        },
        scopes: [
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.PROFILE,
        ],
        callbackUrls: ['https://placeholder.example.com/auth/callback'],
        logoutUrls: ['https://placeholder.example.com/'],
      },
      supportedIdentityProviders: [cognito.UserPoolClientIdentityProvider.COGNITO],
      preventUserExistenceErrors: true,
    });

    /**
     * Cognito Hosted UI Domain
     * - Uses account-specific domain prefix
     * - Provides OAuth2 login/logout pages
     */
    const userPoolDomain = new cognito.UserPoolDomain(this, 'StaticSiteUserPoolDomain', {
      userPool,
      cognitoDomain: {
        domainPrefix: `static-site-${accountId}`,
      },
    });

    // ===========================
    // S3 BUCKET FOR STATIC FILES
    // ===========================

    /**
     * S3 Bucket for static file storage
     * - All public access blocked (files served through API Gateway)
     * - Server-side encryption enabled
     * - Lifecycle rule to cleanup incomplete uploads
     * - Auto-delete on stack deletion (for dev/test environments)
     */
    const staticFilesBucket = new s3.Bucket(this, 'StaticSiteFilesBucket', {
      bucketName: `static-site-${accountId}`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      versioned: false,
      lifecycleRules: [
        {
          id: 'DeleteIncompleteMultipartUploads',
          abortIncompleteMultipartUploadAfter: cdk.Duration.days(7),
          enabled: true,
        },
      ],
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // ===========================
    // DYNAMODB TABLE FOR USER SESSIONS
    // ===========================

    /**
     * DynamoDB table for server-side session storage
     * - Stores JWT tokens securely (not exposed to browser)
     * - sessionId as partition key for direct lookup
     * - TTL for automatic session cleanup
     * - Pay-per-request billing (cost-effective for low traffic)
     */
    const userSessionsTable = new dynamodb.Table(this, 'UserSessionsTable', {
      tableName: 'static-site-sessions',
      partitionKey: {
        name: 'sessionId',
        type: dynamodb.AttributeType.STRING,
      },
      // No sort key - sessionId is unique identifier for direct lookup
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expiresAt',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ===========================
    // LAMBDA LAYER FOR DEPENDENCIES
    // ===========================

    /**
     * Lambda layer containing Python dependencies
     * - Shared across all Lambda functions
     * - Includes JWT handling, HTTP clients, etc.
     *
     * Bundling prefers a local `pip` and falls back to Docker when pip is
     * unavailable, so `cdk synth` works on machines (and CI runners) without a
     * Docker daemon. The local path pins the wheel platform to the Lambda
     * target rather than the host, so a build on macOS or arm64 still produces
     * the manylinux x86-64 binaries the runtime needs - `cryptography` ships
     * native code, and host-native wheels would fail to import at runtime.
     */
    const dependenciesLayer = new lambda.LayerVersion(this, 'DependenciesLayer', {
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda'), {
        bundling: {
          image: PYTHON_RUNTIME.bundlingImage,
          command: [
            'bash', '-c',
            'pip install -r requirements.txt -t /asset-output/python'
          ],
          local: {
            tryBundle(outputDir: string): boolean {
              const requirements = path.join(__dirname, '../lambda/requirements.txt');
              try {
                execFileSync('python3', [
                  '-m', 'pip', 'install',
                  '-r', requirements,
                  '-t', path.join(outputDir, 'python'),
                  // Resolve wheels for the Lambda runtime, not the build host.
                  '--platform', LAMBDA_WHEEL_PLATFORM,
                  '--python-version', LAMBDA_PYTHON_VERSION,
                  '--implementation', 'cp',
                  '--only-binary=:all:',
                  '--upgrade',
                  '--quiet',
                ], { stdio: 'inherit' });
                return true;
              } catch {
                // pip missing or resolution failed - let CDK use Docker.
                return false;
              }
            },
          },
        },
      }),
      compatibleRuntimes: [PYTHON_RUNTIME],
      description: 'Dependencies for Lambda functions',
    });

    // ===========================
    // LAMBDA FUNCTIONS
    // ===========================

    /**
     * Common environment variables for all Lambda functions
     * - Cognito configuration for authentication
     * - S3 bucket for static files
     * - DynamoDB table for sessions
     */
    const commonLambdaEnv = {
      COGNITO_USER_POOL_ID: userPool.userPoolId,
      COGNITO_CLIENT_ID: userPoolClient.userPoolClientId,
      COGNITO_DOMAIN: userPoolDomain.domainName,
      STATIC_BUCKET: staticFilesBucket.bucketName,
      USER_SESSIONS_TABLE: userSessionsTable.tableName,
    };

    /**
     * Explicit log group for a Lambda function.
     *
     * Log groups that Lambda creates implicitly retain records forever, which
     * quietly accrues CloudWatch storage cost on a project whose whole premise
     * is a near-zero bill. These expire after a month and are removed with the
     * stack.
     */
    const makeLogGroup = (id: string) => new logs.LogGroup(this, id, {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    /**
     * Lambda Authorizer Function
     * - Validates JWT tokens from Cognito
     * - Returns IAM policy for API Gateway
     * - No caching to ensure fresh authorization checks
     */
    const authorizerLambda = new lambda.Function(this, 'AuthorizerFunction', {
      runtime: PYTHON_RUNTIME,
      handler: 'authorizer.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda')),
      layers: [dependenciesLayer],
      environment: commonLambdaEnv,
      timeout: cdk.Duration.seconds(30),
      memorySize: 512,
      description: 'JWT authorizer for API Gateway',
      logGroup: makeLogGroup('AuthorizerLogGroup'),
    });

    /**
     * Auth Callback Function
     * - Handles OAuth2 callback from Cognito
     * - Exchanges authorization code for tokens
     * - Stores tokens in DynamoDB, sets session cookie
     */
    const authCallbackLambda = new lambda.Function(this, 'AuthCallbackFunction', {
      runtime: PYTHON_RUNTIME,
      handler: 'auth_callback.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda')),
      layers: [dependenciesLayer],  // Needs jose for JWT decoding
      environment: commonLambdaEnv,
      timeout: cdk.Duration.seconds(30),
      memorySize: 256,
      description: 'OAuth2 callback handler - stores tokens server-side',
      logGroup: makeLogGroup('AuthCallbackLogGroup'),
    });

    /**
     * Auth Decider Function
     * - Decides whether to refresh tokens or redirect to login
     * - Looks up session from DynamoDB
     * - Refreshes tokens and updates DynamoDB
     */
    const authDeciderLambda = new lambda.Function(this, 'AuthDeciderFunction', {
      runtime: PYTHON_RUNTIME,
      handler: 'auth_decider.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda')),
      layers: [dependenciesLayer],  // Needs jose for JWT decoding
      environment: commonLambdaEnv,
      timeout: cdk.Duration.seconds(30),
      memorySize: 256,
      description: 'Token refresh handler - updates tokens in DynamoDB',
      logGroup: makeLogGroup('AuthDeciderLogGroup'),
    });

    /**
     * API Lambda Function
     * - Handles authenticated API endpoints
     * - User info, session check, token refresh
     * - Access to sessions table for state management
     */
    const apiLambda = new lambda.Function(this, 'ApiFunction', {
      runtime: PYTHON_RUNTIME,
      handler: 'api_handler.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda')),
      environment: commonLambdaEnv,
      timeout: cdk.Duration.seconds(30),
      memorySize: 512,
      description: 'Main API handler for auth endpoints',
      logGroup: makeLogGroup('ApiFunctionLogGroup'),
      layers: [dependenciesLayer],
    });

    /**
     * Logout Lambda Function
     * - Handles user logout requests
     * - Deletes session from DynamoDB
     * - Clears session cookie
     */
    const logoutLambda = new lambda.Function(this, 'LogoutFunction', {
      runtime: PYTHON_RUNTIME,
      handler: 'logout.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda')),
      environment: commonLambdaEnv,
      timeout: cdk.Duration.seconds(30),
      memorySize: 256,
      description: 'Handles user logout and session cleanup',
      logGroup: makeLogGroup('LogoutLogGroup'),
      layers: [dependenciesLayer],
    });

    // ===========================
    // IAM PERMISSIONS
    // ===========================

    /**
     * Grant DynamoDB access to all auth-related Lambdas
     * Following principle of least privilege - each Lambda gets only required permissions
     * - Authorizer: reads session to validate tokens, updates lastAccessedAt
     * - Auth Callback: creates session after OAuth callback
     * - Auth Decider: reads/updates session for token refresh
     * - API Lambda: reads session for user info endpoint
     */

    // Authorizer: only needs GetItem and UpdateItem
    authorizerLambda.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'dynamodb:GetItem',
        'dynamodb:UpdateItem'
      ],
      resources: [userSessionsTable.tableArn]
    }));

    // Auth Callback: only needs PutItem to create new sessions
    authCallbackLambda.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'dynamodb:PutItem'
      ],
      resources: [userSessionsTable.tableArn]
    }));

    // Auth Decider: only needs GetItem and UpdateItem for token refresh
    authDeciderLambda.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'dynamodb:GetItem',
        'dynamodb:UpdateItem'
      ],
      resources: [userSessionsTable.tableArn]
    }));

    // API Lambda: full access for user info endpoint
    userSessionsTable.grantReadWriteData(apiLambda);

    // Logout Lambda: only needs DeleteItem to remove sessions
    logoutLambda.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'dynamodb:DeleteItem'
      ],
      resources: [userSessionsTable.tableArn]
    }));

    /**
     * Grant authorizer Lambda access to Cognito
     * - Get user information for authorization
     * - Describe user pool for configuration
     */
    authorizerLambda.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'cognito-idp:GetUser',
        'cognito-idp:DescribeUserPool',
      ],
      resources: [userPool.userPoolArn],
    }));

    // ===========================
    // API GATEWAY
    // ===========================

    /**
     * Lambda Authorizer for API Gateway
     * - Request-based authorization
     * - No caching for security
     * - Checks all incoming requests
     */
    const lambdaAuthorizer = new apigateway.RequestAuthorizer(this, 'LambdaAuthorizer', {
      handler: authorizerLambda,
      identitySources: [],
      authorizerName: 'StaticSiteAuthorizer',
      resultsCacheTtl: cdk.Duration.seconds(0),
    });

    /**
     * API Gateway REST API
     * - Entry point for all traffic
     * - CORS configured securely with restricted methods
     * - Handles both static files and API endpoints
     */
    const api = new apigateway.RestApi(this, 'StaticSiteApi', {
      restApiName: 'Serverless Auth Site API',
      description: 'API Gateway for serverless authenticated static site with Cognito',
      // No defaultCorsPreflightOptions: the frontend is served from this same
      // API Gateway origin, so every browser call is same-origin and no CORS
      // preflight is involved. The previous configuration paired
      // `Access-Control-Allow-Origin: *` with
      // `Access-Control-Allow-Credentials: true`, which browsers reject outright
      // for credentialed requests - and, had a browser honoured it, would have
      // let any site on the internet read authenticated responses.
      //
      // To serve the frontend from a different origin, add
      // `defaultCorsPreflightOptions` here with an explicit `allowOrigins` list
      // naming that origin. Never combine `allowCredentials` with a wildcard.
      binaryMediaTypes: ['*/*'],
      deployOptions: {
        // Method-level throttling on the stage. Unlike usage plan throttling,
        // this applies to every caller rather than only to requests carrying an
        // API key - see the rate limiting section below.
        methodOptions: {
          '/auth/callback/GET': {
            throttlingRateLimit: PUBLIC_ENDPOINT_RATE_LIMIT,
            throttlingBurstLimit: PUBLIC_ENDPOINT_BURST_LIMIT,
          },
          '/auth/decider/GET': {
            throttlingRateLimit: PUBLIC_ENDPOINT_RATE_LIMIT,
            throttlingBurstLimit: PUBLIC_ENDPOINT_BURST_LIMIT,
          },
        },
      },
    });

    // ===========================
    // S3 INTEGRATION FOR STATIC FILES
    // ===========================

    /**
     * IAM role for API Gateway to access S3
     * - Allows API Gateway to retrieve objects from static files bucket
     * - Read-only access
     */
    const s3IntegrationRole = new iam.Role(this, 'S3IntegrationRole', {
      assumedBy: new iam.ServicePrincipal('apigateway.amazonaws.com'),
      description: 'Role for API Gateway to access S3',
    });

    s3IntegrationRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['s3:GetObject'],
      resources: [`${staticFilesBucket.bucketArn}/*`],
    }));

    // ===========================
    // API GATEWAY RESPONSES
    // ===========================

    /**
     * Configure 401 Unauthorized response
     * - Redirects to Cognito login page
     * - Placeholder URL updated by custom resource
     * - No caching for security
     */
    api.addGatewayResponse('UnauthorizedResponse', {
      type: apigateway.ResponseType.UNAUTHORIZED,
      statusCode: '302',
      responseHeaders: {
        'Location': "'https://placeholder.com'",
        'Cache-Control': "'no-cache, no-store, must-revalidate'",
      },
    });

    /**
     * Configure 403 Forbidden response
     * - Also redirects to Cognito login page
     * - Handles access denied scenarios
     * - No caching for security
     */
    api.addGatewayResponse('ForbiddenResponse', {
      type: apigateway.ResponseType.ACCESS_DENIED,
      statusCode: '302',
      responseHeaders: {
        'Location': "'https://placeholder.com'",
        'Cache-Control': "'no-cache, no-store, must-revalidate'",
      },
    });

    // Note: We don't configure MISSING_AUTHENTICATION_TOKEN response because it interferes
    // with public routes like /auth/callback. The authorizer will handle missing tokens
    // by returning Unauthorized, which triggers the correct redirect.

    // ===========================
    // API ROUTES
    // ===========================

    /**
     * Auth Routes (Public - No Authorizer)
     * - /auth/callback: OAuth2 callback from Cognito
     * - /auth/decider: Token refresh or login redirect logic
     */
    const authResource = api.root.addResource('auth');
    authResource.addResource('callback').addMethod('GET',
      new apigateway.LambdaIntegration(authCallbackLambda));

    authResource.addResource('decider').addMethod('GET',
      new apigateway.LambdaIntegration(authDeciderLambda));

    /**
     * API Routes (Protected - Requires Authentication)
     * - /api/auth/user: Get current user information
     * - /api/auth/check: Check authentication status
     * - /api/auth/refresh: Refresh access tokens
     * - /api/auth/logout: Logout and clear session
     */
    const apiResource = api.root.addResource('api');

    const authApiResource = apiResource.addResource('auth');
    authApiResource.addResource('user').addMethod('GET',
      new apigateway.LambdaIntegration(apiLambda), {
        authorizer: lambdaAuthorizer,
      });
    authApiResource.addResource('check').addMethod('GET',
      new apigateway.LambdaIntegration(apiLambda), {
        authorizer: lambdaAuthorizer,
      });
    authApiResource.addResource('refresh').addMethod('POST',
      new apigateway.LambdaIntegration(apiLambda), {
        authorizer: lambdaAuthorizer,
      });
    authApiResource.addResource('logout').addMethod('POST',
      new apigateway.LambdaIntegration(logoutLambda), {
        authorizer: lambdaAuthorizer,
      });

    // ===========================
    // RATE LIMITING FOR PUBLIC ENDPOINTS
    // ===========================

    /**
     * Rate limiting for the public auth endpoints is configured as stage-level
     * method throttling in `deployOptions.methodOptions` above, not as a usage
     * plan.
     *
     * Usage plan throttling is *per-client*: AWS applies it only to requests
     * that carry an API key associated with the plan. These endpoints are
     * deliberately unauthenticated and send no API key, so a usage plan would
     * never have matched a single request - the limits looked enforced but were
     * inert. Stage-level method throttling applies to all callers, which is what
     * protecting an unauthenticated endpoint requires.
     *
     * https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html
     *
     * Note this is a throughput limit, not a daily quota; daily quotas are only
     * expressible per API key. For a hard ceiling on public traffic, put AWS WAF
     * in front of the API.
     */

    // ===========================
    // STATIC FILE ROUTES (S3 INTEGRATION)
    // ===========================

    /**
     * Root route (/) - serves index.html
     * - Protected by Lambda authorizer
     * - Returns HTML with proper content type
     */
    const rootS3Integration = new apigateway.AwsIntegration({
      service: 's3',
      region: this.region,
      integrationHttpMethod: 'GET',
      path: `${staticFilesBucket.bucketName}/index.html`,
      options: {
        credentialsRole: s3IntegrationRole,
        integrationResponses: [
          {
            statusCode: '200',
            responseParameters: {
              'method.response.header.Content-Type': "'text/html; charset=utf-8'",
              'method.response.header.X-Frame-Options': "'DENY'",
              'method.response.header.X-Content-Type-Options': "'nosniff'",
              'method.response.header.Strict-Transport-Security': "'max-age=31536000; includeSubDomains'",
              'method.response.header.Referrer-Policy': "'no-referrer'",
              'method.response.header.Cache-Control': "'no-store'",
            },
          },
        ],
      },
    });

    api.root.addMethod('GET', rootS3Integration, {
      authorizer: lambdaAuthorizer,
      methodResponses: [
        {
          statusCode: '200',
          responseParameters: {
            'method.response.header.Content-Type': true,
            'method.response.header.X-Frame-Options': true,
            'method.response.header.X-Content-Type-Options': true,
            'method.response.header.Strict-Transport-Security': true,
            'method.response.header.Referrer-Policy': true,
            'method.response.header.Cache-Control': true,
          },
        },
      ],
    });

    /**
     * CSS files route (/css/{file})
     * - Protected by Lambda authorizer
     * - Returns CSS with proper content type
     * - 1 hour cache control
     */
    const cssResource = api.root.addResource('css');
    const cssProxy = cssResource.addResource('{file}');
    cssProxy.addMethod('GET', new apigateway.AwsIntegration({
      service: 's3',
      integrationHttpMethod: 'GET',
      path: `${staticFilesBucket.bucketName}/css/{file}`,
      options: {
        credentialsRole: s3IntegrationRole,
        requestParameters: {
          'integration.request.path.file': 'method.request.path.file',
        },
        integrationResponses: [
          {
            statusCode: '200',
            responseParameters: {
              'method.response.header.Content-Type': "'text/css'",
              'method.response.header.Cache-Control': "'public, max-age=3600'",
              'method.response.header.X-Content-Type-Options': "'nosniff'",
              'method.response.header.Strict-Transport-Security': "'max-age=31536000; includeSubDomains'",
            },
          },
        ],
      },
    }), {
      authorizer: lambdaAuthorizer,
      requestParameters: {
        'method.request.path.file': true,
      },
      methodResponses: [
        {
          statusCode: '200',
          responseParameters: {
            'method.response.header.Content-Type': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.X-Content-Type-Options': true,
            'method.response.header.Strict-Transport-Security': true,
          },
        },
      ],
    });

    /**
     * JavaScript files route (/js/{file})
     * - Protected by Lambda authorizer
     * - Returns JS with proper content type
     * - 1 hour cache control
     */
    const jsResource = api.root.addResource('js');
    const jsProxy = jsResource.addResource('{file}');
    jsProxy.addMethod('GET', new apigateway.AwsIntegration({
      service: 's3',
      integrationHttpMethod: 'GET',
      path: `${staticFilesBucket.bucketName}/js/{file}`,
      options: {
        credentialsRole: s3IntegrationRole,
        requestParameters: {
          'integration.request.path.file': 'method.request.path.file',
        },
        integrationResponses: [
          {
            statusCode: '200',
            responseParameters: {
              'method.response.header.Content-Type': "'application/javascript'",
              'method.response.header.Cache-Control': "'public, max-age=3600'",
              'method.response.header.X-Content-Type-Options': "'nosniff'",
              'method.response.header.Strict-Transport-Security': "'max-age=31536000; includeSubDomains'",
            },
          },
        ],
      },
    }), {
      authorizer: lambdaAuthorizer,
      requestParameters: {
        'method.request.path.file': true,
      },
      methodResponses: [
        {
          statusCode: '200',
          responseParameters: {
            'method.response.header.Content-Type': true,
            'method.response.header.Cache-Control': true,
            'method.response.header.X-Content-Type-Options': true,
            'method.response.header.Strict-Transport-Security': true,
          },
        },
      ],
    });

    // ===========================
    // DEPLOY STATIC FILES TO S3
    // ===========================

    /**
     * Bucket deployment for static files
     * - Deploys files from frontend/src directory
     * - Runs during CDK deploy
     * - Auto-deletes old files
     */
    new s3deploy.BucketDeployment(this, 'DeployStaticFiles', {
      sources: [
        // index.html is deployed separately so its Content-Security-Policy can
        // be injected at synth time - see indexHtmlWithCsp().
        s3deploy.Source.asset(FRONTEND_DIR, { exclude: ['index.html'] }),
        s3deploy.Source.data('index.html', indexHtmlWithCsp()),
      ],
      destinationBucket: staticFilesBucket,
      retainOnDelete: false,
    });

    // ===========================
    // CUSTOM RESOURCE TO UPDATE COGNITO URLS
    // ===========================

    /**
     * Login entry point.
     *
     * Always start a login here rather than at the Cognito hosted UI directly.
     * The decider mints the OAuth `state` nonce and the matching cookie that
     * /auth/callback requires; a hand-built hosted-UI URL carries no state and
     * the callback will reject it.
     */
    const loginUrl = `${api.url}auth/decider`;

    /**
     * Custom Resource Lambda
     * - Updates API Gateway responses with correct Cognito login URL
     * - Updates Cognito User Pool Client callback URLs
     * - Runs automatically on stack create/update
     * - Ensures all URLs are consistent after deployment
     */
    const updateCognitoUrlsLambda = new lambda.Function(this, 'UpdateCognitoUrlsFunction', {
      runtime: PYTHON_RUNTIME,
      handler: 'update_cognito_urls.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda')),
      timeout: cdk.Duration.minutes(5),
      environment: {
        ApiId: api.restApiId,
        ApiUrl: api.url,
        UserPoolId: userPool.userPoolId,
        ClientId: userPoolClient.userPoolClientId,
        Region: this.region,
        StageName: api.deploymentStage.stageName,
      },
      // No synth-time timestamp here. The trigger keys off
      // `handler.currentVersion`, whose hash already covers this environment
      // block, so it re-runs whenever the API URL or Cognito IDs change - which
      // is exactly when it needs to. A timestamp made the template differ on
      // every synth, which made `cdk diff` useless and republished a Lambda
      // version plus re-ran the trigger on every no-op deploy.
      memorySize: 256,
      description: 'Updates API Gateway responses with correct Cognito URLs',
      logGroup: makeLogGroup('UpdateCognitoUrlsLogGroup'),
    });

    /**
     * Grant custom resource Lambda permissions for API Gateway
     * - Update gateway responses
     * - Create deployments to apply changes
     */
    updateCognitoUrlsLambda.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'apigateway:UpdateGatewayResponse',
        'apigateway:CreateDeployment',
        'apigateway:GetGatewayResponse',
        'apigateway:PATCH',
        'apigateway:POST',
      ],
      resources: [`arn:aws:apigateway:${this.region}::/restapis/${api.restApiId}/*`],
    }));

    /**
     * Grant custom resource Lambda permissions for Cognito
     * - Read User Pool Client configuration
     * - Update callback URLs
     */
    updateCognitoUrlsLambda.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'cognito-idp:DescribeUserPoolClient',
        'cognito-idp:UpdateUserPoolClient',
      ],
      resources: [userPool.userPoolArn],
    }));

    /**
     * CDK Trigger for custom resource
     * - Executes during deployment
     * - Async invocation (doesn't block deployment)
     * - Runs after all dependencies are created
     */
    const cdkTrigger = new triggers.Trigger(this, "UpdateUrlsTrigger", {
      handler: updateCognitoUrlsLambda,
      timeout: cdk.Duration.minutes(10),
      invocationType: triggers.InvocationType.EVENT // async invocation
    });

    // Ensure trigger runs after all resources are created
    cdkTrigger.executeAfter(api);
    cdkTrigger.executeAfter(userPool);
    cdkTrigger.executeAfter(userPoolClient);
    cdkTrigger.executeAfter(userPoolDomain);
    cdkTrigger.executeAfter(staticFilesBucket);

    // ===========================
    // OUTPUTS
    // ===========================

    new cdk.CfnOutput(this, 'SiteUrl', {
      value: api.url,
      description: 'Secure static site URL',
    });

    new cdk.CfnOutput(this, 'UserPoolId', {
      value: userPool.userPoolId,
      description: 'Cognito User Pool ID',
    });

    new cdk.CfnOutput(this, 'UserPoolClientId', {
      value: userPoolClient.userPoolClientId,
      description: 'Cognito User Pool Client ID',
    });

    new cdk.CfnOutput(this, 'LoginUrl', {
      value: loginUrl,
      description: 'Login entry point - starts the OAuth flow with a state nonce',
    });

    new cdk.CfnOutput(this, 'AutoConfigurationNote', {
      value: 'Cognito redirect URLs are automatically configured by custom resource',
      description: 'Automatic configuration enabled',
    });

    new cdk.CfnOutput(this, 'StaticFilesBucket', {
      value: staticFilesBucket.bucketName,
      description: 'S3 bucket for static files',
    });

    new cdk.CfnOutput(this, 'RateLimitingNote', {
      value: 'Public auth endpoints (/auth/callback, /auth/decider) throttled to 1 req/sec with 2 burst capacity',
      description: 'Rate limiting configuration for public endpoints',
    });
  }
}
