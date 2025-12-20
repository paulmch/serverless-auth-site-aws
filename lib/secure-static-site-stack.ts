import * as cdk from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';
import * as triggers from "aws-cdk-lib/triggers";
import { Construct } from 'constructs';
import * as path from 'path';

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
     */
    const dependenciesLayer = new lambda.LayerVersion(this, 'DependenciesLayer', {
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda'), {
        bundling: {
          image: lambda.Runtime.PYTHON_3_11.bundlingImage,
          command: [
            'bash', '-c',
            'pip install -r requirements.txt -t /asset-output/python'
          ],
        },
      }),
      compatibleRuntimes: [lambda.Runtime.PYTHON_3_11],
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
     * Lambda Authorizer Function
     * - Validates JWT tokens from Cognito
     * - Returns IAM policy for API Gateway
     * - No caching to ensure fresh authorization checks
     */
    const authorizerLambda = new lambda.Function(this, 'AuthorizerFunction', {
      runtime: lambda.Runtime.PYTHON_3_11,
      handler: 'authorizer.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda')),
      layers: [dependenciesLayer],
      environment: commonLambdaEnv,
      timeout: cdk.Duration.seconds(30),
      memorySize: 512,
      description: 'JWT authorizer for API Gateway',
    });

    /**
     * Auth Callback Function
     * - Handles OAuth2 callback from Cognito
     * - Exchanges authorization code for tokens
     * - Stores tokens in DynamoDB, sets session cookie
     */
    const authCallbackLambda = new lambda.Function(this, 'AuthCallbackFunction', {
      runtime: lambda.Runtime.PYTHON_3_11,
      handler: 'auth_callback.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda')),
      layers: [dependenciesLayer],  // Needs jose for JWT decoding
      environment: commonLambdaEnv,
      timeout: cdk.Duration.seconds(30),
      memorySize: 256,
      description: 'OAuth2 callback handler - stores tokens server-side',
    });

    /**
     * Auth Decider Function
     * - Decides whether to refresh tokens or redirect to login
     * - Looks up session from DynamoDB
     * - Refreshes tokens and updates DynamoDB
     */
    const authDeciderLambda = new lambda.Function(this, 'AuthDeciderFunction', {
      runtime: lambda.Runtime.PYTHON_3_11,
      handler: 'auth_decider.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda')),
      layers: [dependenciesLayer],  // Needs jose for JWT decoding
      environment: commonLambdaEnv,
      timeout: cdk.Duration.seconds(30),
      memorySize: 256,
      description: 'Token refresh handler - updates tokens in DynamoDB',
    });

    /**
     * API Lambda Function
     * - Handles authenticated API endpoints
     * - User info, session check, token refresh
     * - Access to sessions table for state management
     */
    const apiLambda = new lambda.Function(this, 'ApiFunction', {
      runtime: lambda.Runtime.PYTHON_3_11,
      handler: 'api_handler.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda')),
      environment: commonLambdaEnv,
      timeout: cdk.Duration.seconds(30),
      memorySize: 512,
      description: 'Main API handler for auth endpoints',
      layers: [dependenciesLayer],
    });

    // ===========================
    // IAM PERMISSIONS
    // ===========================

    /**
     * Grant DynamoDB access to all auth-related Lambdas
     * - Authorizer: reads session to validate tokens
     * - Auth Callback: creates session after OAuth callback
     * - Auth Decider: reads/updates session for token refresh
     * - API Lambda: reads session for user info endpoint
     */
    userSessionsTable.grantReadWriteData(authorizerLambda);
    userSessionsTable.grantReadWriteData(authCallbackLambda);
    userSessionsTable.grantReadWriteData(authDeciderLambda);
    userSessionsTable.grantReadWriteData(apiLambda);

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
     * - CORS enabled for all origins (configure as needed)
     * - Handles both static files and API endpoints
     */
    const api = new apigateway.RestApi(this, 'StaticSiteApi', {
      restApiName: 'Serverless Auth Site API',
      description: 'API Gateway for serverless authenticated static site with Cognito',
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
        allowHeaders: ['Content-Type', 'Authorization', 'Cookie'],
        allowCredentials: true,
      },
      binaryMediaTypes: ['*/*'],
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
    const authCallbackMethod = authResource.addResource('callback').addMethod('GET',
      new apigateway.LambdaIntegration(authCallbackLambda));

    const authDeciderMethod = authResource.addResource('decider').addMethod('GET',
      new apigateway.LambdaIntegration(authDeciderLambda));

    /**
     * API Routes (Protected - Requires Authentication)
     * - /api/auth/user: Get current user information
     * - /api/auth/check: Check authentication status
     * - /api/auth/refresh: Refresh access tokens
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

    // ===========================
    // RATE LIMITING FOR PUBLIC ENDPOINTS
    // ===========================

    /**
     * Usage Plan for Rate Limiting
     * - Protects public auth endpoints from abuse
     * - 1 request/second sustained rate
     * - 2 request burst capacity
     * - 3600 requests/day quota
     */
    const publicEndpointsUsagePlan = new apigateway.UsagePlan(this, 'PublicEndpointsUsagePlan', {
      name: 'Public Auth Endpoints Rate Limiting',
      description: 'Rate limiting for public auth endpoints (1 req/sec as recommended by AWS)',
      throttle: {
        rateLimit: 1,      // 1 request per second sustained
        burstLimit: 2,     // Allow 2 requests in initial burst
      },
      quota: {
        limit: 3600,       // 3600 requests per hour (1 per second * 3600 seconds)
        period: apigateway.Period.DAY,
      },
    });

    /**
     * Associate usage plan with API stage
     * - Applies rate limits to callback and decider endpoints
     */
    publicEndpointsUsagePlan.addApiStage({
      api: api,
      stage: api.deploymentStage,
      throttle: [
        {
          method: authCallbackMethod,
          throttle: {
            rateLimit: 1,
            burstLimit: 2,
          }
        },
        {
          method: authDeciderMethod,
          throttle: {
            rateLimit: 1,
            burstLimit: 2,
          }
        }
      ]
    });

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
              'method.response.header.Content-Type': "'text/html'",
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
      sources: [s3deploy.Source.asset(path.join(__dirname, '../frontend/src'))],
      destinationBucket: staticFilesBucket,
      retainOnDelete: false,
    });

    // ===========================
    // CUSTOM RESOURCE TO UPDATE COGNITO URLS
    // ===========================

    /**
     * Cognito login URL
     * - Authorization code grant flow
     * - Redirects to /auth/callback after login
     * - Requests email, openid, and profile scopes
     */
    const cognitoLoginUrl = `https://${userPoolDomain.domainName}.auth.${this.region}.amazoncognito.com/login?response_type=code&client_id=${userPoolClient.userPoolClientId}&redirect_uri=${api.url}auth/callback&scope=email+openid+profile`;

    /**
     * Custom Resource Lambda
     * - Updates API Gateway responses with correct Cognito login URL
     * - Updates Cognito User Pool Client callback URLs
     * - Runs automatically on stack create/update
     * - Ensures all URLs are consistent after deployment
     */
    const updateCognitoUrlsLambda = new lambda.Function(this, 'UpdateCognitoUrlsFunction', {
      runtime: lambda.Runtime.PYTHON_3_11,
      handler: 'update_cognito_urls.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda')),
      timeout: cdk.Duration.minutes(5),
      environment: {
        ApiId: api.restApiId,
        ApiUrl: api.url,
        CognitoLoginUrl: cognitoLoginUrl,
        UserPoolId: userPool.userPoolId,
        ClientId: userPoolClient.userPoolClientId,
        Region: this.region,
        // Force update when any of these change
        Timestamp: new Date().toISOString(),
      },
      memorySize: 256,
      description: 'Updates API Gateway responses with correct Cognito URLs',
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

    new cdk.CfnOutput(this, 'CognitoLoginUrl', {
      value: cognitoLoginUrl,
      description: 'Cognito hosted login URL',
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
      value: 'Public auth endpoints (/auth/callback, /auth/decider) limited to 1 req/sec with 2 burst capacity',
      description: 'Rate limiting configuration for public endpoints',
    });
  }
}
