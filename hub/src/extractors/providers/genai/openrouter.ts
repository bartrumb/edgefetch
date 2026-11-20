import { defineAdapter } from '../../types';
import { parseJsonObject } from '../../utils';

export default defineAdapter({
  id: 'openrouter',
  name: 'OpenRouter AI Model Catalog',
  category: 'genai',
  description: 'Upgrades OpenRouter model pages to keyless /api/v1/models specs (context window, token pricing, modalities, and tool support).',
  domains: ['openrouter.ai'],
  exampleUrls: ['https://openrouter.ai/anthropic/claude-3.7-sonnet', 'https://openrouter.ai/models/qwen/qwen-2.5-coder-32b-instruct'],
  resolveTwin({ parts }) {
    const reserved = new Set(['docs', 'rankings', 'chat', 'activity', 'settings', 'keys', 'credits', 'privacy', 'terms', 'about', 'blog', 'pricing', 'providers']);
    let modelId = '';
    if (parts[0] === 'models' && parts.length === 3) {
      modelId = `${parts[1]}/${parts[2]}`;
    } else if (parts.length === 2 && !reserved.has(parts[0]!.toLowerCase())) {
      modelId = `${parts[0]}/${parts[1]}`;
    }
    if (!modelId || !/^[A-Za-z0-9._-]+\/[A-Za-z0-9._:-]+$/.test(modelId)) return null;

    const targetLower = modelId.toLowerCase();
    return {
      id: 'openrouter',
      fetchUrl: 'https://openrouter.ai/api/v1/models',
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        const list = Array.isArray(data?.data) ? (data.data as Array<Record<string, unknown>>) : [];
        const model = list.find((m) => String(m.id ?? '').toLowerCase() === targetLower);
        if (!model) return null;

        const name = String(model.name ?? modelId).trim();
        const ctxLen = typeof model.context_length === 'number' ? model.context_length.toLocaleString('en-US') : '';
        const topProv = (model.top_provider as Record<string, unknown> | undefined) ?? {};
        const maxOut = typeof topProv.max_completion_tokens === 'number' ? topProv.max_completion_tokens.toLocaleString('en-US') : '';
        const pricing = (model.pricing as Record<string, unknown> | undefined) ?? {};
        const arch = (model.architecture as Record<string, unknown> | undefined) ?? {};
        const modality = typeof arch.modality === 'string' ? arch.modality : '';
        const params = Array.isArray(model.supported_parameters) ? model.supported_parameters.map(String) : [];
        const desc = typeof model.description === 'string' ? model.description.trim() : '';

        const perMillion = (val: unknown): string => {
          const n = Number(val);
          if (!Number.isFinite(n) || n < 0) return '';
          if (n === 0) return '$0.00 / 1M tokens';
          return `$${(n * 1_000_000).toFixed(2)} / 1M tokens`;
        };
        const promptPrice = perMillion(pricing.prompt);
        const compPrice = perMillion(pricing.completion);

        const bullets: string[] = [`- **Model ID**: \`${String(model.id)}\``];
        if (ctxLen) bullets.push(`- **Context Window**: ${ctxLen} tokens`);
        if (maxOut) bullets.push(`- **Max Output**: ${maxOut} tokens`);
        if (promptPrice) bullets.push(`- **Input Pricing**: ${promptPrice}`);
        if (compPrice) bullets.push(`- **Output Pricing**: ${compPrice}`);
        if (modality) bullets.push(`- **Modality**: \`${modality}\``);
        if (params.length > 0) bullets.push(`- **Supported Parameters**: \`${params.slice(0, 14).join('`, `')}\``);

        const sections = [`# ${name}`, bullets.join('\n')];
        if (desc) sections.push(`## Description\n\n${desc}`);

        return {
          title: name,
          ...(desc ? { description: desc.slice(0, 260) } : {}),
          markdown: sections.join('\n\n'),
        };
      },
    };
  },
});
