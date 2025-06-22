#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { GitHubMcpMultiuserStack } from '../lib/github-mcp-multiuser-stack';

const app = new cdk.App();
new GitHubMcpMultiuserStack(app, 'GitHubMcpMultiuserStack', {
  env: { 
    account: process.env.CDK_DEFAULT_ACCOUNT, 
    region: process.env.CDK_DEFAULT_REGION || 'us-east-1'
  },
  tags: {
    Project: 'github-mcp-multiuser-test',
    Environment: 'test'
  }
});