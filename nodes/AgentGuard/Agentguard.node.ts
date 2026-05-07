import type {
	IDataObject,
	IExecuteFunctions,
	IHttpRequestOptions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	JsonObject,
} from 'n8n-workflow';
import { NodeApiError, NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';

interface Prompt {
	role: string;
	content: string;
	content_type: string;
}

interface ClassifierResult {
	name: string;
	type: string;
	status: 'success' | 'timeout' | 'error' | 'skipped';
	duration_ms: number;
	applied_threshold?: number;
	scores?: { benign: number; malicious: number };
	block_reasons?: string[];
	details?: Record<string, unknown>;
	error?: string;
	skip_reason?: string;
}

interface ClassifyResponse {
	response_action: 'allow' | 'block';
	response_message: string;
	scores: { benign: number; malicious: number };
	block_reasons: string[];
	classifiers: ClassifierResult[];
	effective_threshold: number;
	event_id?: string;
}

interface ClassifyMetadata {
	user?: { id?: string; username?: string; email?: string; principal_type?: string };
	session?: { id?: string };
	agent?: { id?: string; name?: string };
	request?: { src_app?: string; interface?: string; user_agent?: string; src_ip?: string };
}

interface MetadataCollection {
	userId?: string;
	username?: string;
	userEmail?: string;
	principalType?: string;
	sessionId?: string;
	agentId?: string;
	agentName?: string;
	srcApp?: string;
	requestInterface?: string;
}

export class AgentGuard implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'AppOmni AgentGuard',
		name: 'agentguard',
		icon: 'file:icon.svg',
		group: ['transform'],
		version: 1,
		description: "AppOmni's runtime security solution for n8n workflows that leverage AI agents",
		subtitle: 'Defend your AI agent-enabled workflows against prompt-based attacks and data exfiltration',
		defaults: {
			name: 'AppOmni AgentGuard',
		},
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main, NodeConnectionTypes.Main],
		outputNames: ['Allowed', 'Blocked'],
		usableAsTool: undefined,
		credentials: [
			{
				name: 'agentGuardApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Prompt',
				name: 'prompt',
				type: 'string',
				required: true,
				default: '={{ $json.chatInput ?? $json.prompt ?? $json.message ?? $json.input ?? $json.text ?? $json.output ?? "" }}',
				typeOptions: {
					rows: 4,
				},
				description: 'The prompt to classify. Auto-resolves common upstream fields. Override with a literal or a different expression like {{ $JSON.your_field }} when needed',
			},
			{
				displayName: 'Role',
				name: 'role',
				type: 'options',
				default: 'user',
				options: [
					{ name: 'Assistant', value: 'assistant' },
					{ name: 'System', value: 'system' },
					{ name: 'User', value: 'user' },
				],
				description: 'The role of the prompt\'s author',
			},
			{
				displayName: 'Include Details',
				name: 'includeDetails',
				type: 'boolean',
				default: false,
				description:
					'Whether to include per-classifier details in the response',
			},
			{
				displayName: 'Additional Metadata',
				name: 'metadata',
				type: 'collection',
				placeholder: 'Add Field',
				default: {},
				options: [
					{
						displayName: 'Agent ID',
						name: 'agentId',
						type: 'string',
						default: '',
						description: 'Defaults to the n8n workflow ID if unset',
					},
					{
						displayName: 'Agent Name',
						name: 'agentName',
						type: 'string',
						default: '',
						description: 'Defaults to the n8n workflow name if unset',
					},
					{
						displayName: 'Principal Type',
						name: 'principalType',
						type: 'options',
						default: 'external_user',
						options: [
							{ name: 'Agent', value: 'agent' },
							{ name: 'Anonymous', value: 'anonymous' },
							{ name: 'External User', value: 'external_user' },
							{ name: 'Internal User', value: 'internal_user' },
							{ name: 'Service', value: 'service' },
						],
					},
					{
						displayName: 'Request Interface',
						name: 'requestInterface',
						type: 'options',
						default: 'workflow',
						options: [
							{ name: 'API', value: 'api' },
							{ name: 'Chat', value: 'chat' },
							{ name: 'Email', value: 'email' },
							{ name: 'Event', value: 'event' },
							{ name: 'Scheduled', value: 'scheduled' },
							{ name: 'Workflow', value: 'workflow' },
						],
					},
					{
						displayName: 'Session ID',
						name: 'sessionId',
						type: 'string',
						default: '',
						description: 'Defaults to the n8n execution ID if unset. Override with an expression like {{ $JSON.session_id }} for multi-turn conversations.',
					},
					{
						displayName: 'Source App',
						name: 'srcApp',
						type: 'string',
						default: '',
						description: 'Identifier for the calling application. Defaults to "n8n-workflow-&lt;ID&gt;" if unset.',
					},
					{
						displayName: 'User Email',
						name: 'userEmail',
						type: 'string',
						default: '',
						description: 'Fallback identifier when User ID and Username are unset',
					},
					{
						displayName: 'User ID',
						name: 'userId',
						type: 'string',
						default: '',
						description:
							'End-user identifier. Defaults to the Chat Trigger session ID when present on the input. Required to opt this user into user quarantine. Falls back to Username, then Email if unset',
					},
					{
						displayName: 'Username',
						name: 'username',
						type: 'string',
						default: '',
						description: 'Fallback identifier when User ID is unset',
					},
				],
			},
		],
	};

	private static buildMetadata(meta: MetadataCollection): ClassifyMetadata | undefined {
		const userFields = ['userId', 'username', 'userEmail', 'principalType'] as const;
		const userDefined = userFields.some((k) => Boolean(meta[k]));
		const sessionDefined = Boolean(meta.sessionId);
		const agentDefined = Boolean(meta.agentId || meta.agentName);
		const requestDefined = Boolean(meta.srcApp || meta.requestInterface);

		if (!userDefined && !sessionDefined && !agentDefined && !requestDefined) return undefined;

		const metadata: ClassifyMetadata = {};
		if (userDefined) {
			metadata.user = {};
			if (meta.userId) metadata.user.id = meta.userId;
			if (meta.username) metadata.user.username = meta.username;
			if (meta.userEmail) metadata.user.email = meta.userEmail;
			if (meta.principalType) metadata.user.principal_type = meta.principalType;
		}
		if (sessionDefined) metadata.session = { id: meta.sessionId };
		if (agentDefined) {
			metadata.agent = {};
			if (meta.agentId) metadata.agent.id = meta.agentId;
			if (meta.agentName) metadata.agent.name = meta.agentName;
		}
		if (requestDefined) {
			metadata.request = {};
			if (meta.srcApp) metadata.request.src_app = meta.srcApp;
			if (meta.requestInterface) metadata.request.interface = meta.requestInterface;
		}
		return metadata;
	}

	private static isBlocked(response: ClassifyResponse): boolean {
		// fail-open
		return response?.response_action === 'block';
	}

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const input = this.getInputData();
		const allowed: INodeExecutionData[] = [];
		const blocked: INodeExecutionData[] = [];

		const credentials = await this.getCredentials('agentGuardApi');

		for (let i = 0; i < input.length; i++) {
			try {
				const content = this.getNodeParameter('prompt', i) as string;
				if (!content || !content.trim()) {
					throw new NodeOperationError(
						this.getNode(),
						'Prompt is empty — provide a non-empty string to classify',
						{ itemIndex: i },
					);
				}

				const role = this.getNodeParameter('role', i, 'user') as string;
				const includeDetails = this.getNodeParameter('includeDetails', i, false) as boolean;
				const metaCollection = this.getNodeParameter(
					'metadata',
					i,
					{},
				) as MetadataCollection;

				const workflow = this.getWorkflow();
				const chatSessionId =
					typeof input[i].json.sessionId === 'string'
						? (input[i].json.sessionId as string)
						: undefined;
				const executionId = this.getExecutionId();
				const enrichedMeta: MetadataCollection = {
					...metaCollection,
					agentId: metaCollection.agentId || workflow.id || undefined,
					agentName: metaCollection.agentName || workflow.name || undefined,
					sessionId: metaCollection.sessionId || chatSessionId || executionId || undefined,
					userId: metaCollection.userId || chatSessionId || undefined,
					srcApp:
						metaCollection.srcApp ||
						(workflow.id ? `n8n-workflow-${workflow.id}` : 'n8n'),
				};

				const prompt: Prompt = {
					role,
					content: content,
					content_type: 'text/plain',
				};

				const body: IDataObject = {
					messages: [prompt],
					include_details: includeDetails,
				};

				const metadata = AgentGuard.buildMetadata(enrichedMeta);
				if (metadata !== undefined) {
					body.metadata = metadata as unknown as IDataObject;
				}

				const tenantUrl = String(credentials.tenantUrl).replace(/\/+$/, '');
				const requestOptions: IHttpRequestOptions = {
					method: 'POST',
					url: `${tenantUrl}/api/v1/ai/prompts/agents/classify`,
					body,
					json: true,
				};

				const response = (await this.helpers.httpRequestWithAuthentication.call(
					this,
					'agentGuardApi',
					requestOptions,
				)) as ClassifyResponse;

				const isBlocked = AgentGuard.isBlocked(response);

				const output: INodeExecutionData = {
					json: {
						...input[i].json,
						agentguard: {
							blocked: isBlocked,
							prompt,
							response_action: response.response_action,
							response_message: response.response_message,
							block_reasons: response.block_reasons,
							event_id: response.event_id,
							response: response as unknown as IDataObject,
						},
					},
					pairedItem: { item: i },
				};

				if (isBlocked) {
					blocked.push(output);
				} else {
					allowed.push(output);
				}
			} catch (error) {
				if (this.continueOnFail()) {
					allowed.push({
						json: {
							...input[i].json,
							agentguard: {
								blocked: false,
								error: (error as Error).message,
							},
						},
						pairedItem: { item: i },
					});
					continue;
				}

				if (error instanceof NodeOperationError) {
					throw error;
				}
				throw new NodeApiError(this.getNode(), error as JsonObject, { itemIndex: i });
			}
		}

		return [allowed, blocked];
	}
}
