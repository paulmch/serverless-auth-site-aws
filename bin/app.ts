#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { SecureStaticSiteStack } from '../lib/secure-static-site-stack';

const app = new cdk.App();

new SecureStaticSiteStack(app, 'SecureStaticSiteStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION || 'us-east-1'
  },
  description: 'Secure static website with Cognito authentication'
});
