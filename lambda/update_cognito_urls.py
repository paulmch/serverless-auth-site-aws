import json
import boto3
import urllib3
import os
from typing import Dict, Any

def send_response(event: Dict[str, Any], context: Any, response_status: str, response_data: Dict[str, Any] = None, reason: str = None) -> None:
    """Send response back to CloudFormation."""
    if response_data is None:
        response_data = {}

    response_body = {
        'Status': response_status,
        'Reason': reason or f'See CloudWatch Log Stream: {context.log_stream_name}',
        'PhysicalResourceId': event.get('PhysicalResourceId', context.log_stream_name),
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': response_data
    }

    response_body_str = json.dumps(response_body)

    http = urllib3.PoolManager()
    try:
        response = http.request(
            'PUT',
            event['ResponseURL'],
            body=response_body_str,
            headers={
                'Content-Type': 'application/json',
                'Content-Length': str(len(response_body_str))
            }
        )
        print(f"Response sent to CloudFormation: {response.status}")
    except Exception as e:
        print(f"Failed to send response to CloudFormation: {str(e)}")


def update_cognito_user_pool_client(user_pool_id: str, client_id: str, api_url: str, region: str) -> None:
    """Update Cognito User Pool Client with correct callback URLs."""
    client = boto3.client('cognito-idp', region_name=region)

    try:
        print(f"Updating Cognito User Pool Client {client_id} with callback URLs...")

        # Get current client configuration
        response = client.describe_user_pool_client(
            UserPoolId=user_pool_id,
            ClientId=client_id
        )

        current_config = response['UserPoolClient']

        # Update with new callback URLs (only include valid parameters)
        update_params = {
            'UserPoolId': user_pool_id,
            'ClientId': client_id,
            'ClientName': current_config['ClientName'],
            'ExplicitAuthFlows': current_config.get('ExplicitAuthFlows', []),
            'SupportedIdentityProviders': current_config.get('SupportedIdentityProviders', ['COGNITO']),
            'CallbackURLs': [f"{api_url}auth/callback"],
            'LogoutURLs': [api_url],
            'DefaultRedirectURI': f"{api_url}auth/callback",
            'AllowedOAuthFlows': current_config.get('AllowedOAuthFlows', ['code']),
            'AllowedOAuthScopes': current_config.get('AllowedOAuthScopes', ['email', 'openid', 'profile']),
            'AllowedOAuthFlowsUserPoolClient': current_config.get('AllowedOAuthFlowsUserPoolClient', True)
        }

        # Only include token validity if they exist and are valid
        if current_config.get('RefreshTokenValidity') and 1 <= current_config['RefreshTokenValidity'] <= 315360000:
            update_params['RefreshTokenValidity'] = current_config['RefreshTokenValidity']
        if current_config.get('AccessTokenValidity') and 1 <= current_config['AccessTokenValidity'] <= 86400:
            update_params['AccessTokenValidity'] = current_config['AccessTokenValidity']
        if current_config.get('IdTokenValidity') and 1 <= current_config['IdTokenValidity'] <= 86400:
            update_params['IdTokenValidity'] = current_config['IdTokenValidity']
        if current_config.get('TokenValidityUnits'):
            update_params['TokenValidityUnits'] = current_config['TokenValidityUnits']
        if current_config.get('ReadAttributes'):
            update_params['ReadAttributes'] = current_config['ReadAttributes']
        if current_config.get('WriteAttributes'):
            update_params['WriteAttributes'] = current_config['WriteAttributes']
        if current_config.get('PreventUserExistenceErrors'):
            update_params['PreventUserExistenceErrors'] = current_config['PreventUserExistenceErrors']
        if current_config.get('EnableTokenRevocation') is not None:
            update_params['EnableTokenRevocation'] = current_config['EnableTokenRevocation']
        if current_config.get('EnablePropagateAdditionalUserContextData') is not None:
            update_params['EnablePropagateAdditionalUserContextData'] = current_config['EnablePropagateAdditionalUserContextData']

        # Remove empty AnalyticsConfiguration if present
        if current_config.get('AnalyticsConfiguration'):
            update_params['AnalyticsConfiguration'] = current_config['AnalyticsConfiguration']

        client.update_user_pool_client(**update_params)

        print("Successfully updated Cognito User Pool Client callback URLs")

    except Exception as e:
        print(f"Failed to update Cognito User Pool Client: {str(e)}")
        raise


def update_gateway_responses(api_id: str, api_url: str, region: str) -> None:
    """Update API Gateway responses to redirect to auth decider."""
    client = boto3.client('apigateway', region_name=region)

    # Response types that need URL updates
    response_types = ['UNAUTHORIZED', 'ACCESS_DENIED']

    # Build decider URL - the decider will handle redirect_to parameter dynamically
    decider_url = f"{api_url}auth/decider"

    for response_type in response_types:
        try:
            print(f"Updating {response_type} response to redirect to auth decider...")

            client.update_gateway_response(
                restApiId=api_id,
                responseType=response_type,
                patchOperations=[
                    {
                        'op': 'replace',
                        'path': '/responseParameters/gatewayresponse.header.Location',
                        'value': f"'{decider_url}'"
                    }
                ]
            )

            print(f"Successfully updated {response_type} response to redirect to: {decider_url}")

        except Exception as e:
            print(f"Failed to update {response_type} response: {str(e)}")
            raise

    # Deploy the changes
    try:
        print("Deploying API changes...")
        deployment = client.create_deployment(
            restApiId=api_id,
            stageName='prod',
            description='Updated Cognito redirect URLs'
        )
        print(f"Deployment created: {deployment['id']}")

    except Exception as e:
        print(f"Failed to deploy API changes: {str(e)}")
        raise


def handler(event: Dict[str, Any], context: Any) -> None:
    """Lambda function to update Cognito URLs in API Gateway responses and User Pool Client."""
    print(f"Event received: {json.dumps(event, default=str)}")

    try:
        api_id = os.environ['ApiId']
        api_url = os.environ['ApiUrl']
        # CognitoLoginUrl is passed but not used here - gateway responses redirect to /auth/decider
        user_pool_id = os.environ['UserPoolId']
        client_id = os.environ['ClientId']
        region = os.environ['Region']

        print(f"Updating configurations for API {api_id}...")

        # Update Cognito User Pool Client callback URLs
        update_cognito_user_pool_client(user_pool_id, client_id, api_url, region)

        # Update the gateway responses to redirect to auth decider
        update_gateway_responses(api_id, api_url, region)

        # Send success response
        send_response(event, context, 'SUCCESS', {
            'Message': f'Successfully updated configurations for API {api_id}'
        })

    except Exception as e:
        error_message = f"Error in custom resource: {str(e)}"
        print(error_message)
        send_response(event, context, 'FAILED', reason=error_message)
