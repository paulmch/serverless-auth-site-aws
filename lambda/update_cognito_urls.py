"""Post-deployment configuration for Cognito and API Gateway.

This runs as a CDK ``triggers.Trigger`` handler, not as a CloudFormation custom
resource: the trigger provider calls Lambda ``Invoke`` directly with no payload
and reports success/failure from the invocation itself. It must therefore not
speak the CloudFormation custom-resource response protocol (no ResponseURL,
StackId or RequestId exist in the event) - raising on failure is how a trigger
signals an error.
"""

import boto3
import os
from typing import Any, Dict


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


def update_gateway_responses(api_id: str, api_url: str, region: str, stage_name: str) -> None:
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
            stageName=stage_name,
            description='Updated Cognito redirect URLs'
        )
        print(f"Deployment created: {deployment['id']}")

    except Exception as e:
        print(f"Failed to deploy API changes: {str(e)}")
        raise


def handler(event: Dict[str, Any], context: Any) -> Dict[str, str]:
    """Update Cognito callback URLs and API Gateway responses after deployment.

    Invoked by the CDK trigger with an empty event. Any exception raised here
    fails the invocation, which is how the trigger reports an error.
    """
    api_id = os.environ['ApiId']
    api_url = os.environ['ApiUrl']
    user_pool_id = os.environ['UserPoolId']
    client_id = os.environ['ClientId']
    region = os.environ['Region']
    stage_name = os.environ['StageName']

    print(f"Updating configurations for API {api_id}...")

    # Update Cognito User Pool Client callback URLs
    update_cognito_user_pool_client(user_pool_id, client_id, api_url, region)

    # Update the gateway responses to redirect to auth decider
    update_gateway_responses(api_id, api_url, region, stage_name)

    message = f'Successfully updated configurations for API {api_id}'
    print(message)
    return {'Message': message}
