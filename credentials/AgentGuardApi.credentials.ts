import type {
	IAuthenticateGeneric,
	Icon,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class AgentGuardApi implements ICredentialType {
	name = 'agentGuardApi';
	displayName = 'AppOmni AgentGuard API';
	documentationUrl = 'https://github.com/appomni/n8n-nodes-agentguard#credentials';
	icon = 'file:../nodes/AgentGuard/icon.svg' as Icon;

	properties: INodeProperties[] = [
		{
			displayName: 'Tenant URL',
			name: 'tenantUrl',
			type: 'string',
			required: true,
			default: '',
			placeholder: 'https://example.appomni.com',
			description:
				'AppOmni tenant URL',
		},
		{
			displayName: 'Ingest Token',
			name: 'ingestToken',
			type: 'string',
			required: true,
			typeOptions: {
				password: true,
			},
			default: '',
			description: 'AppOmni-issued ingest token',
		},
		{
			displayName: 'Host override',
			name: 'hostOverride',
			type: 'string',
			default: '',
			description:
				'Optional override for the X-Host header. Leave blank unless instructed by AppOmni support',
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				'X-AppOmni-Ingest-Token': '={{$credentials.ingestToken}}',
				'X-Host': '={{$credentials.hostOverride}}',
			},
		},
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.tenantUrl}}',
			url: '/api/v1/ai/prompts/agents/classify',
			method: 'POST',
			json: true,
			body: {
				messages: [
					{ role: 'user', content: 'AppOmni AgentGuard credential test', content_type: 'text/plain' },
				],
			},
		},
	};
}
