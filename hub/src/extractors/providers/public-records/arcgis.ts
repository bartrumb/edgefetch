import { defineAdapter } from '../../types';
import { formatGfmTable, parseJsonObject, stripTagsInline } from '../../utils';

export default defineAdapter({
  id: 'arcgis',
  name: 'ArcGIS REST FeatureServer & MapServer Layers',
  category: 'public-records',
  description: 'Upgrades public ArcGIS REST FeatureServer/MapServer layer URLs to ?f=json metadata, geometry type, spatial reference, and field schemas.',
  domains: ['services.arcgis.com', '*.arcgis.com'],
  universalEngine: true,
  exampleUrls: ['https://services.arcgis.com/P3ePLMYs2RVChkJx/arcgis/rest/services/USA_States_Generalized/FeatureServer/0'],
  resolveTwin({ url, urlStr }) {
    if (!/\/rest\/services\/.+\/(?:FeatureServer|MapServer)(?:\/\d+)?\/?$/i.test(url.pathname)) {
      return null;
    }
    const fetchUrlObj = new URL(urlStr);
    fetchUrlObj.searchParams.set('f', 'json');
    const baseClean = urlStr.split('?')[0]!.replace(/\/+$/, '');

    return {
      id: 'arcgis',
      fetchUrl: fetchUrlObj.toString(),
      kind: 'json',
      accept: 'application/json',
      formatTwin: (rawBody) => {
        const data = parseJsonObject(rawBody);
        if (!data || data.error) return null;
        const name = String(data.name || data.mapName || data.serviceDescription || 'ArcGIS Service').trim();
        const descRaw = String(data.description || data.serviceDescription || '');
        const desc = descRaw ? stripTagsInline(descRaw) : '';
        const geomType = typeof data.geometryType === 'string' ? data.geometryType : '';
        const maxRec = typeof data.maxRecordCount === 'number' ? String(data.maxRecordCount) : '';
        const capabilities = typeof data.capabilities === 'string' ? data.capabilities : '';
        const srObj = (data.extent as Record<string, unknown> | undefined)?.spatialReference as Record<string, unknown> | undefined;
        const wkid = srObj?.latestWkid ?? srObj?.wkid;

        const bullets: string[] = [`- **REST Endpoint**: \`${baseClean}\``];
        if (geomType) bullets.push(`- **Geometry Type**: \`${geomType}\``);
        if (wkid !== undefined) bullets.push(`- **Spatial Reference (WKID)**: \`EPSG:${String(wkid)}\``);
        if (maxRec) bullets.push(`- **Max Record Count / Query**: ${maxRec}`);
        if (capabilities) bullets.push(`- **Capabilities**: ${capabilities}`);

        const fields = Array.isArray(data.fields) ? (data.fields as Array<Record<string, unknown>>) : [];
        const layers = Array.isArray(data.layers) ? (data.layers as Array<Record<string, unknown>>) : [];

        const sections: string[] = [`# ${name}`, bullets.join('\n')];
        if (desc) sections.push(`## Description\n\n${desc}`);

        if (fields.length > 0) {
          const fRows = fields.slice(0, 40).map((f) => [
            `\`${String(f.name ?? '-')}\``,
            String(f.alias ?? '-'),
            String(f.type ?? '-').replace(/^esriFieldType/i, ''),
          ]);
          sections.push(`## Layer Fields (${fields.length})\n\n${formatGfmTable(['Field', 'Alias', 'Type'], fRows)}`);
        } else if (layers.length > 0) {
          const lRows = layers.slice(0, 30).map((l) => [
            String(l.id ?? '-'),
            `[${String(l.name ?? 'Layer')}](${baseClean}/${String(l.id ?? 0)})`,
            String(l.geometryType ?? '-'),
          ]);
          sections.push(`## Sublayers (${layers.length})\n\n${formatGfmTable(['ID', 'Layer', 'Geometry'], lRows)}`);
        }

        return {
          title: name,
          ...(desc ? { description: desc.slice(0, 260) } : {}),
          markdown: sections.join('\n\n'),
        };
      },
    };
  },
});
